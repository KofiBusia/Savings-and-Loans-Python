"""
Customer management router — CRUD, KYC workflow, profile.
KYC is enforced as a 12-step state machine (api/compliance/kyc_state_machine.py).
All actions are audit-logged (Cybersecurity Act 2020 s.34).
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api import models
from api.compliance.kyc_state_machine import KYCStateMachine
from api.database import get_db
from api.deps import get_current_customer, get_current_customer_any, get_current_user, require_roles
from pydantic import BaseModel
from typing import Optional

from api.schemas.customers import (
    BeneficialOwnerRequest,
    CustomerCreateRequest,
    CustomerListResponse,
    CustomerResponse,
    CustomerUpdateRequest,
    KYCStatusResponse,
    KYCStepRequest,
)


class KYCSubmitRequest(BaseModel):
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    residential_address: Optional[str] = None
    region: Optional[str] = None
    district: Optional[str] = None
    occupation: Optional[str] = None
    monthly_income_ghs: Optional[float] = None
    savings_product_id: Optional[str] = None
from api.security import generate_account_number, hash_password
from api.utils.audit_chain import write_audit
from api.validators.ghana_validators import validate_ghana_phone

log = logging.getLogger(__name__)
router = APIRouter(prefix="/customers", tags=["Customers"])


@router.post("", response_model=CustomerResponse, status_code=status.HTTP_201_CREATED,
             summary="Create customer (field officer onboarding)")
def create_customer(
    body: CustomerCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("FIELD_OFFICER", "ADMIN", "SUPER_ADMIN")),
):
    e164, mno = validate_ghana_phone(body.phone)

    if db.query(models.Customer).filter_by(ghana_card_number=body.ghana_card_number).first():
        raise HTTPException(status_code=409, detail="Ghana Card already registered")
    if db.query(models.Customer).filter_by(phone_e164=e164).first():
        raise HTTPException(status_code=409, detail="Phone number already registered")

    account_number = generate_account_number()
    customer = models.Customer(
        account_number=account_number,
        customer_type=body.customer_type,
        first_name=body.first_name,
        last_name=body.last_name,
        other_names=body.other_names,
        ghana_card_number=body.ghana_card_number,
        phone_e164=e164,
        mno=mno,
        email=body.email,
        date_of_birth=body.date_of_birth,
        gender=body.gender,
        post_gps=body.post_gps,
        region=body.region,
        district=body.district,
        residential_address=body.residential_address,
        employer_name=body.employer_name,
        occupation=body.occupation,
        monthly_income_ghs=body.monthly_income_ghs,
        password_hash=hash_password(body.password),
        onboarded_by=current_user.id,
        kyc_status="PENDING_GHANA_CARD",
    )
    db.add(customer)
    db.flush()

    # Create savings account automatically
    db.add(models.SavingsAccount(
        customer_id=customer.id,
        account_number=generate_account_number("SAV"),
        product_name="Regular Savings",
        status="PENDING_ACTIVATION",
    ))
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="CREATE",
                actor_id=current_user.id, data={"account_number": account_number})

    return customer


@router.get("", response_model=CustomerListResponse, summary="List customers")
def list_customers(
    q: str | None = Query(default=None, description="Search by name, phone, account number"),
    kyc_status: str | None = None,
    risk_level: str | None = None,
    is_active: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    query = db.query(models.Customer)

    if q:
        like = f"%{q}%"
        query = query.filter(
            (models.Customer.first_name.ilike(like)) |
            (models.Customer.last_name.ilike(like)) |
            (models.Customer.account_number.ilike(like)) |
            (models.Customer.phone_e164.ilike(like))
        )
    if kyc_status:
        query = query.filter_by(kyc_status=kyc_status)
    if risk_level:
        query = query.filter_by(risk_level=risk_level)
    if is_active is not None:
        query = query.filter_by(is_active=is_active)

    total = query.count()
    items = query.offset((page - 1) * page_size).limit(page_size).all()

    return CustomerListResponse(total=total, page=page, page_size=page_size, items=items)


# ── Customer self-service — MUST be before /{customer_id} ────────────────────

@router.get("/me/profile", response_model=CustomerResponse, summary="Customer profile (mobile)")
def customer_profile(
    current_customer: models.Customer = Depends(get_current_customer_any),
):
    """Works for all customers including those pending KYC."""
    return current_customer


@router.post("/me/kyc/submit", response_model=CustomerResponse,
             summary="Customer submits KYC details for admin review")
def submit_kyc(
    body: KYCSubmitRequest,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer_any),
):
    if current_customer.kyc_status not in ("PENDING_GHANA_CARD", "REJECTED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot submit KYC when status is '{current_customer.kyc_status}'. "
                   "Contact support if you believe this is an error.",
        )
    if body.date_of_birth:
        try:
            from datetime import datetime as _dt
            current_customer.date_of_birth = _dt.fromisoformat(body.date_of_birth)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date_of_birth format. Use YYYY-MM-DD.")
    if body.gender:
        current_customer.gender = body.gender
    if body.residential_address:
        current_customer.residential_address = body.residential_address
    if body.region:
        current_customer.region = body.region
    if body.district:
        current_customer.district = body.district
    if body.occupation:
        current_customer.occupation = body.occupation
    if body.monthly_income_ghs is not None:
        current_customer.monthly_income_ghs = body.monthly_income_ghs
    if body.savings_product_id:
        current_customer.savings_product_id = body.savings_product_id

    current_customer.kyc_status = "PENDING_REVIEW"
    db.commit()

    write_audit(db, table_name="customers", record_id=current_customer.id,
                action="KYC_SUBMITTED", actor_id=current_customer.id, actor_type="CUSTOMER",
                data={"kyc_status": "PENDING_REVIEW"})
    db.commit()

    return current_customer


@router.get("/kyc/pending", response_model=CustomerListResponse,
            summary="List customers pending KYC review (admin)")
def list_pending_kyc(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(
        "FIELD_OFFICER", "COMPLIANCE_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    query = db.query(models.Customer).filter_by(kyc_status="PENDING_REVIEW")
    total = query.count()
    items = query.order_by(models.Customer.created_at.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return CustomerListResponse(total=total, page=page, page_size=page_size, items=items)


@router.get("/{customer_id}", response_model=CustomerResponse, summary="Get customer by ID")
def get_customer(
    customer_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    customer = _get_or_404(db, customer_id)
    return customer


@router.put("/{customer_id}", response_model=CustomerResponse, summary="Update customer profile")
def update_customer(
    customer_id: str,
    body: CustomerUpdateRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("FIELD_OFFICER", "ADMIN", "SUPER_ADMIN")),
):
    customer = _get_or_404(db, customer_id)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(customer, k, v)
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="UPDATE",
                actor_id=current_user.id, data=changes)

    return customer


@router.post("/{customer_id}/suspend", summary="Suspend a customer account")
def suspend_customer(
    customer_id: str,
    reason: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("COMPLIANCE_OFFICER", "SUPER_ADMIN")),
):
    customer = _get_or_404(db, customer_id)
    customer.is_suspended = True
    customer.suspension_reason = reason
    customer.suspended_at = datetime.utcnow()
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="SUSPEND",
                actor_id=current_user.id, data={"reason": reason})

    return {"detail": "Account suspended", "customer_id": customer_id}


@router.post("/{customer_id}/unsuspend", summary="Unsuspend a customer account")
def unsuspend_customer(
    customer_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("COMPLIANCE_OFFICER", "SUPER_ADMIN")),
):
    customer = _get_or_404(db, customer_id)
    customer.is_suspended = False
    customer.suspension_reason = None
    customer.suspended_at = None
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="UNSUSPEND",
                actor_id=current_user.id, data={})

    return {"detail": "Account reinstated", "customer_id": customer_id}


# ─── KYC Workflow ──────────────────────────────────────────────────────────────

@router.get("/{customer_id}/kyc", response_model=KYCStatusResponse,
            summary="Get KYC status")
def get_kyc_status(
    customer_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    customer = _get_or_404(db, customer_id)
    completed_steps = [
        r.step for r in db.query(models.KYCRecord)
        .filter_by(customer_id=customer_id, status="COMPLETED")
        .all()
    ]

    fsm = KYCStateMachine(customer=customer, db=db, actor_id="SYSTEM")
    next_step = fsm.next_step()

    return KYCStatusResponse(
        customer_id=customer_id,
        kyc_status=customer.kyc_status,
        current_step=customer.kyc_status,
        steps_completed=completed_steps,
        next_step=next_step,
        kyc_completed_at=customer.kyc_completed_at,
    )


@router.post("/{customer_id}/kyc/advance", response_model=KYCStatusResponse,
             summary="Advance KYC to next step")
def advance_kyc(
    customer_id: str,
    body: KYCStepRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "FIELD_OFFICER", "COMPLIANCE_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    customer = _get_or_404(db, customer_id)

    if customer.is_suspended:
        raise HTTPException(status_code=403, detail="Cannot advance KYC on suspended account")

    fsm = KYCStateMachine(customer=customer, db=db, actor_id=current_user.id)
    result = fsm.transition(step=body.step, step_data=body.step_data)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)

    db.commit()

    completed_steps = [
        r.step for r in db.query(models.KYCRecord)
        .filter_by(customer_id=customer_id, status="COMPLETED")
        .all()
    ]

    return KYCStatusResponse(
        customer_id=customer_id,
        kyc_status=customer.kyc_status,
        current_step=customer.kyc_status,
        steps_completed=completed_steps,
        next_step=fsm.next_step(),
        kyc_completed_at=customer.kyc_completed_at,
    )


# ─── Beneficial Owners (SME) ───────────────────────────────────────────────────

@router.post("/{customer_id}/beneficial-owners", status_code=201,
             summary="Add beneficial owner (SME — AML Act 1044 s.22)")
def add_beneficial_owner(
    customer_id: str,
    body: BeneficialOwnerRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "COMPLIANCE_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    customer = _get_or_404(db, customer_id)
    if customer.customer_type == "INDIVIDUAL":
        raise HTTPException(status_code=400, detail="Individual customers do not have beneficial owners")

    owner = models.BeneficialOwner(
        customer_id=customer_id,
        full_name=body.full_name,
        ghana_card_number=body.ghana_card_number,
        ownership_pct=body.ownership_pct,
        is_pep=body.is_pep,
        nationality=body.nationality,
        role=body.role,
    )
    db.add(owner)
    db.commit()

    write_audit(db, table_name="beneficial_owners", record_id=owner.id, action="CREATE",
                actor_id=current_user.id,
                data={"customer_id": customer_id, "full_name": body.full_name})

    return {"id": owner.id, "detail": "Beneficial owner added"}


# ─── KYC Admin Actions ────────────────────────────────────────────────────────

@router.post("/{customer_id}/kyc/approve", response_model=CustomerResponse,
             summary="Approve customer KYC — activates account")
def approve_kyc(
    customer_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "COMPLIANCE_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    customer = _get_or_404(db, customer_id)
    if customer.kyc_status != "PENDING_REVIEW":
        raise HTTPException(
            status_code=400,
            detail=f"Customer KYC status is '{customer.kyc_status}', not PENDING_REVIEW.",
        )
    customer.kyc_status = "ACTIVE"
    customer.is_active = True
    customer.kyc_completed_at = datetime.utcnow()

    savings = db.query(models.SavingsAccount).filter_by(customer_id=customer_id).first()
    if savings:
        savings.status = "ACTIVE"
        if customer.savings_product_id:
            product = db.query(models.SavingsProduct).filter_by(id=customer.savings_product_id).first()
            if product:
                savings.product_name = product.name
                savings.interest_rate_pa = product.interest_rate_pa
                savings.minimum_balance = product.minimum_balance

    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id,
                action="KYC_APPROVED", actor_id=current_user.id,
                data={"approved_by": current_user.email, "kyc_status": "ACTIVE"})
    db.commit()

    return customer


@router.post("/{customer_id}/kyc/reject", response_model=CustomerResponse,
             summary="Reject customer KYC")
def reject_kyc(
    customer_id: str,
    reason: str = "KYC requirements not met",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(
        "COMPLIANCE_OFFICER", "ADMIN", "SUPER_ADMIN"
    )),
):
    customer = _get_or_404(db, customer_id)
    if customer.kyc_status != "PENDING_REVIEW":
        raise HTTPException(
            status_code=400,
            detail=f"Customer KYC status is '{customer.kyc_status}', not PENDING_REVIEW.",
        )
    customer.kyc_status = "REJECTED"
    customer.is_active = False
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id,
                action="KYC_REJECTED", actor_id=current_user.id,
                data={"reason": reason, "kyc_status": "REJECTED"})
    db.commit()

    return customer


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _get_or_404(db: Session, customer_id: str) -> models.Customer:
    customer = db.query(models.Customer).filter_by(id=customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer
