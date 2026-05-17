"""
Commission management router.
Loan officers earn commissions on interest from repayment N onwards (policy-driven).
"""
from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api import models
from api.database import get_db
from api.deps import get_current_user, require_roles
from api.schemas.commissions import (
    CommissionPayoutRequest,
    CommissionPolicyCreate,
    CommissionPolicyResponse,
    CommissionResponse,
    CommissionSummary,
    OfficerAssignRequest,
)
from api.utils.audit_chain import write_audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/commissions", tags=["Commissions"])


# ─── Policy CRUD ──────────────────────────────────────────────────────────────

@router.get("/policy", response_model=list[CommissionPolicyResponse],
            summary="List all commission policies")
def list_policies(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return db.query(models.CommissionPolicy).order_by(
        models.CommissionPolicy.created_at.desc()
    ).all()


@router.post("/policy", response_model=CommissionPolicyResponse, status_code=201,
             summary="Create commission policy (SUPER_ADMIN)")
def create_policy(
    body: CommissionPolicyCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("SUPER_ADMIN")),
):
    # If creating an active global policy, deactivate other active global ones
    if body.is_active and body.applies_to_product_id is None:
        db.query(models.CommissionPolicy).filter_by(
            is_active=True, applies_to_product_id=None
        ).update({"is_active": False})

    policy = models.CommissionPolicy(
        name=body.name,
        commission_rate=body.commission_rate,
        trigger_repayment=body.trigger_repayment,
        is_active=body.is_active,
        applies_to_product_id=body.applies_to_product_id,
        created_by=current_user.id,
    )
    db.add(policy)
    db.commit()
    write_audit(db, table_name="commission_policies", record_id=policy.id,
                action="CREATE", actor_id=current_user.id,
                data={"rate": str(body.commission_rate), "trigger": body.trigger_repayment})
    return policy


@router.put("/policy/{policy_id}", response_model=CommissionPolicyResponse,
            summary="Update commission policy (SUPER_ADMIN)")
def update_policy(
    policy_id: str,
    body: CommissionPolicyCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("SUPER_ADMIN")),
):
    policy = db.query(models.CommissionPolicy).filter_by(id=policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if body.is_active and body.applies_to_product_id is None:
        db.query(models.CommissionPolicy).filter(
            models.CommissionPolicy.id != policy_id,
            models.CommissionPolicy.is_active == True,
            models.CommissionPolicy.applies_to_product_id == None,
        ).update({"is_active": False})

    policy.name = body.name
    policy.commission_rate = body.commission_rate
    policy.trigger_repayment = body.trigger_repayment
    policy.is_active = body.is_active
    policy.applies_to_product_id = body.applies_to_product_id
    policy.updated_by = current_user.id
    db.commit()

    write_audit(db, table_name="commission_policies", record_id=policy.id,
                action="UPDATE", actor_id=current_user.id,
                data={"rate": str(body.commission_rate), "trigger": body.trigger_repayment})
    return policy


# ─── Officer Assignments ───────────────────────────────────────────────────────

@router.post("/assign/{customer_id}", summary="Assign loan officer to customer")
def assign_officer(
    customer_id: str,
    body: OfficerAssignRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("ADMIN", "SUPER_ADMIN")),
):
    customer = db.query(models.Customer).filter_by(id=customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    officer = db.query(models.User).filter_by(id=body.officer_id).first()
    if not officer:
        raise HTTPException(status_code=404, detail="Officer not found")
    if "FIELD_OFFICER" not in (officer.roles or []):
        raise HTTPException(status_code=400, detail="User is not a FIELD_OFFICER")

    old_officer = customer.assigned_officer_id
    customer.assigned_officer_id = body.officer_id
    db.commit()

    write_audit(db, table_name="customers", record_id=customer_id,
                action="OFFICER_ASSIGNED", actor_id=current_user.id,
                data={"officer_id": body.officer_id, "previous": old_officer})
    return {"detail": "Officer assigned", "customer_id": customer_id, "officer_id": body.officer_id}


# ─── Commission Records ────────────────────────────────────────────────────────

@router.get("/my", response_model=list[CommissionResponse],
            summary="Loan officer views their own commissions")
def my_commissions(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.LoanOfficerCommission).filter_by(officer_id=current_user.id)
    if status:
        q = q.filter_by(status=status)
    return q.order_by(models.LoanOfficerCommission.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()


@router.get("/my/summary", response_model=CommissionSummary,
            summary="Loan officer commission summary")
def my_commission_summary(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return _build_summary(db, current_user.id, current_user.full_name)


@router.get("/my/performance", summary="Loan officer performance dashboard")
def my_performance(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Returns performance KPIs for the currently logged-in loan officer."""
    # Customers assigned to this officer
    assigned = db.query(models.Customer).filter_by(
        assigned_officer_id=current_user.id
    ).all()
    customer_ids = [c.id for c in assigned]

    # Loans originated by this officer (applied_by)
    originated = db.query(models.Loan).filter_by(applied_by=current_user.id).all()

    # Loan status breakdown for assigned customers
    if customer_ids:
        from sqlalchemy import and_
        cust_loans = db.query(models.Loan).filter(
            models.Loan.customer_id.in_(customer_ids)
        ).all()
    else:
        cust_loans = []

    active   = sum(1 for l in cust_loans if l.status in ("DISBURSED", "ACTIVE"))
    overdue  = sum(1 for l in cust_loans if l.days_past_due and l.days_past_due > 0)
    settled  = sum(1 for l in cust_loans if l.status == "SETTLED")
    total_cl = len(cust_loans)
    collection_rate = round(settled / total_cl * 100, 1) if total_cl else 0.0

    # Commission totals
    comms   = db.query(models.LoanOfficerCommission).filter_by(officer_id=current_user.id).all()
    pending = sum(c.commission_amount for c in comms if c.status == "PENDING") or Decimal("0")
    paid    = sum(c.commission_amount for c in comms if c.status == "PAID")    or Decimal("0")

    # Recent repayments collected (last 30 days)
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=30)
    recent_collections = db.query(models.LoanRepayment).filter(
        models.LoanRepayment.collected_by == current_user.id,
        models.LoanRepayment.created_at >= cutoff,
    ).count()

    return {
        "officer_name": current_user.full_name or current_user.email,
        "customers_assigned": len(assigned),
        "loans_originated": len(originated),
        "active_loans": active,
        "overdue_loans": overdue,
        "settled_loans": settled,
        "total_loans": total_cl,
        "collection_rate_pct": collection_rate,
        "collections_last_30d": recent_collections,
        "commission_pending": float(pending),
        "commission_paid": float(paid),
        "commission_total": float(pending + paid),
        "commission_count": len(comms),
    }


@router.get("/officer/{officer_id}", response_model=list[CommissionResponse],
            summary="View commissions for a specific officer (admin)")
def officer_commissions(
    officer_id: str,
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("ADMIN", "SUPER_ADMIN")),
):
    q = db.query(models.LoanOfficerCommission).filter_by(officer_id=officer_id)
    if status:
        q = q.filter_by(status=status)
    return q.order_by(models.LoanOfficerCommission.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()


@router.get("/summary/all", response_model=list[CommissionSummary],
            summary="Commission summary for all officers (admin)")
def all_officer_summaries(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("ADMIN", "SUPER_ADMIN")),
):
    officer_ids = [
        row[0] for row in db.query(models.LoanOfficerCommission.officer_id).distinct().all()
    ]
    results = []
    for oid in officer_ids:
        officer = db.query(models.User).filter_by(id=oid).first()
        results.append(_build_summary(db, oid, officer.full_name if officer else None))
    return results


@router.post("/payout", summary="Mark commissions as paid (SUPER_ADMIN / ADMIN)")
def payout_commissions(
    body: CommissionPayoutRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("ADMIN", "SUPER_ADMIN")),
):
    now = datetime.utcnow()
    updated = 0
    for cid in body.commission_ids:
        commission = db.query(models.LoanOfficerCommission).filter_by(
            id=cid, status="PENDING"
        ).first()
        if commission:
            commission.status = "PAID"
            commission.paid_at = now
            commission.paid_by = current_user.id
            commission.payment_reference = body.payment_reference
            commission.notes = body.notes
            updated += 1
    db.commit()

    write_audit(db, table_name="loan_officer_commissions", record_id="BATCH",
                action="PAYOUT", actor_id=current_user.id,
                data={"count": updated, "reference": body.payment_reference})
    return {"detail": f"{updated} commissions marked as PAID", "reference": body.payment_reference}


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _build_summary(db: Session, officer_id: str, officer_name: Optional[str]) -> CommissionSummary:
    comms = db.query(models.LoanOfficerCommission).filter_by(officer_id=officer_id).all()
    pending = sum(c.commission_amount for c in comms if c.status == "PENDING") or Decimal("0")
    paid = sum(c.commission_amount for c in comms if c.status == "PAID") or Decimal("0")
    return CommissionSummary(
        officer_id=officer_id,
        officer_name=officer_name,
        total_pending=pending,
        total_paid=paid,
        total_earned=pending + paid,
        commission_count=len(comms),
    )


def compute_and_store_commission(
    db: Session,
    loan: models.Loan,
    repayment: models.LoanRepayment,
    repayment_number: int,
) -> Optional[models.LoanOfficerCommission]:
    """Called after each repayment. Creates a commission if policy qualifies."""
    # Find applicable policy: product-specific first, then global default
    policy = (
        db.query(models.CommissionPolicy)
        .filter_by(is_active=True, applies_to_product_id=loan.product_id)
        .first()
        or db.query(models.CommissionPolicy)
        .filter_by(is_active=True, applies_to_product_id=None)
        .first()
    )
    if not policy:
        return None

    if repayment_number < policy.trigger_repayment:
        return None  # not yet eligible

    # Find the officer: prefer customer's assigned officer, fall back to loan.applied_by
    customer = db.query(models.Customer).filter_by(id=loan.customer_id).first()
    officer_id = (customer.assigned_officer_id if customer else None) or loan.applied_by
    if not officer_id:
        return None

    interest = repayment.interest_component or Decimal("0")
    if interest <= 0:
        return None

    commission_amount = (interest * policy.commission_rate).quantize(Decimal("0.01"))

    commission = models.LoanOfficerCommission(
        officer_id=officer_id,
        loan_id=loan.id,
        repayment_id=repayment.id,
        policy_id=policy.id,
        repayment_number=repayment_number,
        interest_amount=interest,
        commission_rate=policy.commission_rate,
        commission_amount=commission_amount,
    )
    db.add(commission)
    return commission
