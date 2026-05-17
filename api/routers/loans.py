"""
Loan management router.
All interest calculations use SimpleInterestCalculator — compound interest raises ValueError
and is caught as a 400 error (DCD 2025, Clause 14).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api import models
from api.compliance.aml_engine import AMLEngine
from api.compliance.interest_calculator import SimpleInterestCalculator
from api.config import settings
from api.database import get_db
from api.deps import get_current_customer, get_current_user, require_mfa, require_roles
from api.schemas.loans import (
    CollateralRequest,
    LoanApprovalRequest,
    LoanApplicationRequest,
    LoanDisbursementRequest,
    LoanEligibilityResponse,
    LoanListParams,
    LoanProductCreate,
    LoanProductResponse,
    LoanQuoteResponse,
    LoanRepaymentRequest,
    LoanRepaymentResponse,
    LoanResponse,
    LoanScheduleInstalment,
)
from api.security import generate_loan_number, generate_reference
from api.utils.audit_chain import write_audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/loans", tags=["Loans"])

_calc = SimpleInterestCalculator()


# ─── Loan Products ─────────────────────────────────────────────────────────────

@router.post("/products", response_model=LoanProductResponse, status_code=201,
             summary="Create loan product")
def create_product(
    body: LoanProductCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("CREDIT_MANAGER", "SUPER_ADMIN")),
):
    product = models.LoanProduct(**body.model_dump(), created_by=current_user.id)
    db.add(product)
    db.commit()
    write_audit(db, table_name="loan_products", record_id=product.id, action="CREATE",
                actor_id=current_user.id, data={"name": body.name})
    return product


@router.get("/products", response_model=list[LoanProductResponse], summary="List loan products")
def list_products(
    active_only: bool = True,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    q = db.query(models.LoanProduct)
    if active_only:
        q = q.filter_by(is_active=True)
    return q.all()


@router.get("/products/available", response_model=list[LoanProductResponse],
            summary="List available loan products (customer-accessible)")
def list_products_customer(
    db: Session = Depends(get_db),
    _: models.Customer = Depends(get_current_customer),
):
    return db.query(models.LoanProduct).filter_by(is_active=True).all()


@router.get("/products/{product_id}", response_model=LoanProductResponse,
            summary="Get single loan product")
def get_product(
    product_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    product = db.query(models.LoanProduct).filter_by(id=product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Loan product not found")
    return product


class LoanProductUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    annual_interest_rate: Decimal | None = Field(
        default=None, gt=0, le=Decimal("0.60"),
        description="Max 60% p.a. — BoG cap. DCD 2025 Clause 14.")
    processing_fee_pct: Decimal | None = Field(default=None, ge=0, le=Decimal("0.10"))
    insurance_fee_pct: Decimal | None = Field(default=None, ge=0, le=Decimal("0.05"))
    late_payment_fee_pct: Decimal | None = Field(default=None, ge=0, le=Decimal("0.05"))
    min_amount_ghs: Decimal | None = Field(default=None, gt=0)
    max_amount_ghs: Decimal | None = Field(default=None, gt=0)
    min_tenure_months: int | None = Field(default=None, ge=1)
    max_tenure_months: int | None = Field(default=None, ge=1, le=120)
    requires_collateral: bool | None = None
    requires_guarantor: bool | None = None
    savings_ratio: Decimal | None = Field(default=None, gt=0, le=Decimal("1.0"))
    collateral_ratio: Decimal | None = Field(default=None, gt=0, le=Decimal("1.0"))
    is_active: bool | None = None


@router.patch("/products/{product_id}", response_model=LoanProductResponse,
              summary="Update loan product rates and settings (CREDIT_MANAGER / SUPER_ADMIN)")
def update_product(
    product_id: str,
    body: LoanProductUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("CREDIT_MANAGER", "SUPER_ADMIN")),
):
    product = db.query(models.LoanProduct).filter_by(id=product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Loan product not found")
    changes: dict = {}
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(product, field, value)
        changes[field] = str(value)
    db.commit()
    write_audit(db, table_name="loan_products", record_id=product.id, action="UPDATE",
                actor_id=current_user.id, data=changes)
    return product


# ─── Eligibility ────────────────────────────────────────────────────────────────

def _compute_eligibility(
    db: Session,
    customer: models.Customer,
    product: models.LoanProduct | None = None,
    collateral_value_ghs: Decimal = Decimal("0"),
) -> dict:
    savings_acct = db.query(models.SavingsAccount).filter_by(
        customer_id=customer.id, status="ACTIVE"
    ).first()
    balance = savings_acct.balance if savings_acct else Decimal("0")

    savings_ratio = product.savings_ratio if product else Decimal("0.70")
    collateral_ratio = product.collateral_ratio if product else Decimal("0.50")

    max_savings_loan = (balance * savings_ratio).quantize(Decimal("0.01"))
    max_collateral_loan = (collateral_value_ghs * collateral_ratio).quantize(Decimal("0.01"))

    if collateral_value_ghs > 0:
        effective_max = max_collateral_loan
        note = f"Based on collateral value × {float(collateral_ratio)*100:.0f}%"
    else:
        effective_max = max_savings_loan
        note = f"Based on savings balance × {float(savings_ratio)*100:.0f}%"

    product_max = product.max_amount_ghs if product else None
    final_max = min(effective_max, product_max) if product_max else effective_max

    return {
        "savings_balance": balance,
        "savings_ratio": savings_ratio,
        "max_savings_loan": max_savings_loan,
        "collateral_value_ghs": collateral_value_ghs,
        "collateral_ratio": collateral_ratio,
        "max_collateral_loan": max_collateral_loan,
        "effective_max": effective_max,
        "product_max": product_max,
        "final_max": final_max,
        "note": note,
    }


@router.get("/my/eligibility", response_model=LoanEligibilityResponse,
            summary="Check customer's loan eligibility")
def my_loan_eligibility(
    product_id: str | None = Query(default=None),
    collateral_value_ghs: Decimal = Query(default=Decimal("0"), ge=0),
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    product = db.query(models.LoanProduct).filter_by(id=product_id).first() if product_id else None
    e = _compute_eligibility(db, current_customer, product, collateral_value_ghs)
    return LoanEligibilityResponse(**e)


@router.get("/eligibility/{customer_id}", response_model=LoanEligibilityResponse,
            summary="Check a customer's loan eligibility (staff)")
def customer_loan_eligibility(
    customer_id: str,
    product_id: str | None = Query(default=None),
    collateral_value_ghs: Decimal = Query(default=Decimal("0"), ge=0),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    customer = _get_customer_or_404(db, customer_id)
    product = db.query(models.LoanProduct).filter_by(id=product_id).first() if product_id else None
    e = _compute_eligibility(db, customer, product, collateral_value_ghs)
    return LoanEligibilityResponse(**e)


class CustomerLoanRequest(BaseModel):
    product_id: str
    principal_ghs: Decimal
    tenure_months: int
    purpose: str | None = None
    disbursement_account: str | None = None
    disbursement_channel: str = "MOBILE_MONEY"
    collateral_value_ghs: Decimal = Field(default=Decimal("0"), ge=0,
        description="Estimated value of collateral (0 = no collateral, use savings ratio)")


@router.post("/apply", response_model=LoanResponse, status_code=201,
             summary="Customer submits a loan application for field officer review")
def customer_apply_loan(
    body: CustomerLoanRequest,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    customer = db.query(models.Customer).filter_by(id=current_customer.id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    if customer.kyc_status != "ACTIVE":
        raise HTTPException(
            status_code=400,
            detail=f"KYC verification not complete. Current status: {customer.kyc_status}",
        )

    product = _get_product_or_404(db, body.product_id)
    _validate_loan_params(product, body.principal_ghs, body.tenure_months)

    # Eligibility check
    elig = _compute_eligibility(db, customer, product, body.collateral_value_ghs)
    if body.principal_ghs > elig["effective_max"] and elig["effective_max"] > 0:
        raise HTTPException(
            status_code=400,
            detail=f"Loan amount exceeds eligibility limit of GHS {elig['effective_max']:.2f}. {elig['note']}",
        )

    result = _calc.calculate(
        principal=body.principal_ghs,
        annual_rate_pct=float(product.annual_interest_rate) * 100,
        tenure_months=body.tenure_months,
    )

    processing_fee = (body.principal_ghs * product.processing_fee_pct).quantize(Decimal("0.01"))
    insurance_fee = (body.principal_ghs * product.insurance_fee_pct).quantize(Decimal("0.01"))
    total_repayable = result.total_repayable + processing_fee + insurance_fee

    loan = models.Loan(
        loan_number=generate_loan_number(),
        customer_id=customer.id,
        product_id=product.id,
        principal_ghs=body.principal_ghs,
        annual_interest_rate=product.annual_interest_rate,
        tenure_months=body.tenure_months,
        processing_fee_ghs=processing_fee,
        insurance_fee_ghs=insurance_fee,
        total_interest_ghs=result.total_interest,
        total_repayable_ghs=total_repayable,
        monthly_instalment_ghs=result.instalments[0].total_payment if result.instalments else Decimal("0"),
        apr=result.apr.quantize(Decimal("0.0001")) if result.apr else None,
        outstanding_ghs=total_repayable,
        disbursement_channel=body.disbursement_channel,
        disbursement_account=body.disbursement_account,
        status="APPLICATION",
        schedule_json=[
            {
                "instalment_number": i.period,
                "due_date": i.due_date.isoformat(),
                "principal": str(i.principal_component),
                "interest": str(i.interest_component),
                "total": str(i.total_payment),
                "balance_after": str(i.closing_balance),
            }
            for i in result.instalments
        ],
    )
    db.add(loan)
    db.commit()

    write_audit(db, table_name="loans", record_id=loan.id, action="CUSTOMER_APPLICATION",
                actor_id=customer.id,
                data={"loan_number": loan.loan_number, "principal": str(body.principal_ghs),
                      "purpose": body.purpose, "collateral_value": str(body.collateral_value_ghs)})
    return loan


# ─── Loan Quotes ───────────────────────────────────────────────────────────────

@router.get("/quote", response_model=LoanQuoteResponse,
            summary="Get loan quote (no DB write — DCD 2025 Clause 11 pre-disclosure)")
def get_quote(
    product_id: str,
    principal_ghs: Decimal = Query(gt=0),
    tenure_months: int = Query(ge=1, le=120),
    db: Session = Depends(get_db),
    _: models.Customer = Depends(get_current_customer),
):
    product = _get_product_or_404(db, product_id)
    _validate_loan_params(product, principal_ghs, tenure_months)

    result = _calc.calculate(
        principal=principal_ghs,
        annual_rate_pct=product.annual_interest_rate * 100,
        tenure_months=tenure_months,
    )

    processing_fee = (principal_ghs * product.processing_fee_pct).quantize(Decimal("0.01"))
    insurance_fee = (principal_ghs * product.insurance_fee_pct).quantize(Decimal("0.01"))

    return LoanQuoteResponse(
        principal_ghs=principal_ghs,
        annual_interest_rate=product.annual_interest_rate,
        tenure_months=tenure_months,
        total_interest_ghs=result.total_interest,
        processing_fee_ghs=processing_fee,
        insurance_fee_ghs=insurance_fee,
        total_repayable_ghs=result.total_repayable + processing_fee + insurance_fee,
        monthly_instalment_ghs=result.instalments[0].total_payment if result.instalments else Decimal("0"),
        apr=result.apr.quantize(Decimal("0.0001")) if result.apr else Decimal("0"),
        schedule=[
            LoanScheduleInstalment(
                instalment_number=i.period,
                due_date=i.due_date.isoformat(),
                principal=i.principal_component,
                interest=i.interest_component,
                total=i.total_payment,
                balance_after=i.closing_balance,
            )
            for i in result.instalments
        ],
    )


# ─── Loan Application ──────────────────────────────────────────────────────────

@router.post("", response_model=LoanResponse, status_code=201,
             summary="Apply for a loan")
def apply_for_loan(
    body: LoanApplicationRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "FIELD_OFFICER", "CREDIT_MANAGER", "ADMIN", "SUPER_ADMIN"
    )),
):
    customer = _get_customer_or_404(db, body.customer_id)
    product = _get_product_or_404(db, body.product_id)

    if customer.kyc_status != "ACTIVE":
        raise HTTPException(status_code=400, detail=f"KYC not complete. Current: {customer.kyc_status}")

    _validate_loan_params(product, body.principal_ghs, body.tenure_months)

    result = _calc.calculate(
        principal=body.principal_ghs,
        annual_rate_pct=float(product.annual_interest_rate) * 100,
        tenure_months=body.tenure_months,
    )

    processing_fee = (body.principal_ghs * product.processing_fee_pct).quantize(Decimal("0.01"))
    insurance_fee = (body.principal_ghs * product.insurance_fee_pct).quantize(Decimal("0.01"))
    total_repayable = result.total_repayable + processing_fee + insurance_fee

    loan = models.Loan(
        loan_number=generate_loan_number(),
        customer_id=customer.id,
        product_id=product.id,
        principal_ghs=body.principal_ghs,
        annual_interest_rate=product.annual_interest_rate,
        tenure_months=body.tenure_months,
        processing_fee_ghs=processing_fee,
        insurance_fee_ghs=insurance_fee,
        total_interest_ghs=result.total_interest,
        total_repayable_ghs=total_repayable,
        monthly_instalment_ghs=result.instalments[0].total_payment if result.instalments else Decimal("0"),
        apr=result.apr.quantize(Decimal("0.0001")) if result.apr else None,
        outstanding_ghs=total_repayable,
        disbursement_channel=body.disbursement_channel,
        disbursement_account=body.disbursement_account,
        applied_by=current_user.id,
        status="APPLICATION",
        schedule_json=[
            {
                "instalment_number": i.period,
                "due_date": i.due_date.isoformat(),
                "principal": str(i.principal_component),
                "interest": str(i.interest_component),
                "total": str(i.total_payment),
                "balance_after": str(i.closing_balance),
            }
            for i in result.instalments
        ],
    )
    db.add(loan)
    db.commit()

    write_audit(db, table_name="loans", record_id=loan.id, action="APPLICATION",
                actor_id=current_user.id, data={
                    "loan_number": loan.loan_number, "principal": str(body.principal_ghs),
                    "customer_id": customer.id,
                })

    return loan


@router.get("", response_model=list[LoanResponse], summary="List loans")
def list_loans(
    customer_id: str | None = None,
    loan_status: str | None = Query(default=None, alias="status"),
    overdue_only: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    q = db.query(models.Loan)
    if customer_id:
        q = q.filter_by(customer_id=customer_id)
    if loan_status:
        q = q.filter_by(status=loan_status)
    if overdue_only:
        q = q.filter(models.Loan.days_past_due > 0)
    return q.offset((page - 1) * page_size).limit(page_size).all()


@router.get("/my", response_model=list[LoanResponse], summary="Customer's own loans (mobile)")
def my_loans(
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    return db.query(models.Loan).filter_by(customer_id=current_customer.id).all()


@router.get("/{loan_id}", response_model=LoanResponse, summary="Get loan by ID")
def get_loan(
    loan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return _get_loan_or_404(db, loan_id)


# ─── Approval Workflow ─────────────────────────────────────────────────────────

@router.post("/{loan_id}/approve", response_model=LoanResponse,
             summary="Approve or reject a loan (Credit Manager + MFA)")
def approve_loan(
    loan_id: str,
    body: LoanApprovalRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "CREDIT_MANAGER" not in (current_user.roles or []) and "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires CREDIT_MANAGER or SUPER_ADMIN")

    loan = _get_loan_or_404(db, loan_id)
    if loan.status not in ("APPLICATION", "CREDIT_CHECK", "DOCUMENT_COLLECTION", "CREDIT_COMMITTEE"):
        raise HTTPException(status_code=400, detail=f"Cannot approve loan in status: {loan.status}")

    if body.approved:
        loan.status = "APPROVED"
        loan.approved_at = datetime.utcnow()
        loan.approved_by = current_user.id
        # DCD 2025 Clause 11 — 5-day cooling-off period
        loan.cooling_off_expires_at = datetime.utcnow() + timedelta(days=5)
        action = "APPROVE"
    else:
        loan.status = "REJECTED"
        loan.rejected_by = current_user.id
        loan.rejection_reason = body.rejection_reason
        action = "REJECT"

    db.commit()
    write_audit(db, table_name="loans", record_id=loan.id, action=action,
                actor_id=current_user.id,
                data={"loan_number": loan.loan_number, "notes": body.notes})

    return loan


@router.post("/{loan_id}/disburse", response_model=LoanResponse,
             summary="Disburse loan (SUPER_ADMIN + MFA — irreversible)")
def disburse_loan(
    loan_id: str,
    body: LoanDisbursementRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires SUPER_ADMIN")
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true to proceed")

    loan = _get_loan_or_404(db, loan_id)

    if loan.status != "APPROVED":
        raise HTTPException(status_code=400, detail=f"Cannot disburse loan in status: {loan.status}")

    if loan.cooling_off_expires_at and loan.cooling_off_expires_at > datetime.utcnow():
        if not loan.cooling_off_exercised:
            remaining = (loan.cooling_off_expires_at - datetime.utcnow()).days
            log.info("disbursing loan still within cooling-off period loan_id=%s remaining_days=%d",
                     loan_id, remaining)

    now = datetime.utcnow()
    loan.status = "DISBURSED"
    loan.disbursed_at = now
    loan.disbursed_by = current_user.id
    loan.first_repayment_date = datetime(now.year, now.month + 1, 1) if now.month < 12 else \
        datetime(now.year + 1, 1, 1)
    loan.maturity_date = loan.first_repayment_date + timedelta(days=30 * loan.tenure_months)
    loan.next_due_date = loan.first_repayment_date
    loan.disbursement_account = body.disbursement_account
    loan.disbursement_channel = body.disbursement_channel

    # TODO: call GhIPSS MMI disbursement via asyncio.run in background task

    db.commit()
    write_audit(db, table_name="loans", record_id=loan.id, action="DISBURSE",
                actor_id=current_user.id, data={
                    "loan_number": loan.loan_number,
                    "channel": body.disbursement_channel,
                    "account": body.disbursement_account,
                })

    return loan


# ─── Repayments ────────────────────────────────────────────────────────────────

@router.post("/{loan_id}/repayments", response_model=LoanRepaymentResponse,
             status_code=201, summary="Record a loan repayment")
def record_repayment(
    loan_id: str,
    body: LoanRepaymentRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "TELLER", "FIELD_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    loan = _get_loan_or_404(db, loan_id)
    if loan.status not in ("DISBURSED", "ACTIVE", "OVERDUE"):
        raise HTTPException(status_code=400, detail=f"Cannot record repayment on loan in status: {loan.status}")

    # Simple proportional allocation: interest first, then principal
    outstanding_interest = max(
        Decimal("0"),
        loan.total_interest_ghs - (
            sum(r.interest_component for r in loan.repayments) or Decimal("0")
        ),
    )
    interest_component = min(body.amount_ghs, outstanding_interest)
    principal_component = body.amount_ghs - interest_component

    repayment = models.LoanRepayment(
        loan_id=loan.id,
        reference=generate_reference(),
        paid_date=datetime.utcnow(),
        principal_component=principal_component,
        interest_component=interest_component,
        total_amount=body.amount_ghs,
        channel=body.channel,
        mno_reference=body.mno_reference,
        collected_by=current_user.id,
    )
    db.add(repayment)

    loan.amount_paid_ghs += body.amount_ghs
    loan.outstanding_ghs = max(Decimal("0"), loan.total_repayable_ghs - loan.amount_paid_ghs)

    if loan.outstanding_ghs == 0:
        loan.status = "SETTLED"
        loan.settled_at = datetime.utcnow()
    elif loan.status == "DISBURSED":
        loan.status = "ACTIVE"

    db.commit()

    # AML check
    aml = AMLEngine(db=db)
    aml.process_transaction(
        customer=loan.customer,
        transaction={"id": repayment.id, "type": "LOAN_REPAYMENT", "amount": body.amount_ghs},
        actor_id=current_user.id,
    )

    # Commission calculation
    try:
        from api.routers.commissions import compute_and_store_commission
        repayment_count = db.query(models.LoanRepayment).filter_by(loan_id=loan_id).count()
        compute_and_store_commission(db, loan, repayment, repayment_count)
        db.commit()
    except Exception:
        log.exception("commission_calc_failed repayment_id=%s", repayment.id)

    write_audit(db, table_name="loan_repayments", record_id=repayment.id, action="CREATE",
                actor_id=current_user.id,
                data={"loan_number": loan.loan_number, "amount": str(body.amount_ghs)})

    return repayment


@router.get("/{loan_id}/repayments", response_model=list[LoanRepaymentResponse],
            summary="List repayments for a loan")
def list_repayments(
    loan_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    _get_loan_or_404(db, loan_id)
    return db.query(models.LoanRepayment).filter_by(loan_id=loan_id).all()


# ─── Collateral ────────────────────────────────────────────────────────────────

@router.post("/{loan_id}/collateral", status_code=201, summary="Register collateral")
def add_collateral(
    loan_id: str,
    body: CollateralRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("CREDIT_MANAGER", "SUPER_ADMIN")),
):
    loan = _get_loan_or_404(db, loan_id)
    collateral = models.CollateralRegistry(
        loan_id=loan.id,
        collateral_type=body.collateral_type,
        description=body.description,
        estimated_value_ghs=body.estimated_value_ghs,
        forced_sale_value_ghs=body.forced_sale_value_ghs,
        valuation_date=body.valuation_date,
        valuator_name=body.valuator_name,
    )
    db.add(collateral)
    db.commit()

    write_audit(db, table_name="collateral_registry", record_id=collateral.id, action="CREATE",
                actor_id=current_user.id, data={"loan_id": loan_id, "type": body.collateral_type})

    return {"id": collateral.id, "detail": "Collateral registered"}


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _get_loan_or_404(db: Session, loan_id: str) -> models.Loan:
    loan = db.query(models.Loan).filter_by(id=loan_id).first()
    if not loan:
        raise HTTPException(status_code=404, detail="Loan not found")
    return loan


def _get_product_or_404(db: Session, product_id: str) -> models.LoanProduct:
    product = db.query(models.LoanProduct).filter_by(id=product_id, is_active=True).first()
    if not product:
        raise HTTPException(status_code=404, detail="Loan product not found or inactive")
    return product


def _get_customer_or_404(db: Session, customer_id: str) -> models.Customer:
    customer = db.query(models.Customer).filter_by(id=customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


def _validate_loan_params(product: models.LoanProduct, principal: Decimal, tenure: int) -> None:
    if principal < product.min_amount_ghs or principal > product.max_amount_ghs:
        raise HTTPException(
            status_code=400,
            detail=f"Principal must be between GHS {product.min_amount_ghs} and {product.max_amount_ghs}",
        )
    if tenure < product.min_tenure_months or tenure > product.max_tenure_months:
        raise HTTPException(
            status_code=400,
            detail=f"Tenure must be between {product.min_tenure_months} and {product.max_tenure_months} months",
        )
