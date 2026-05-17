"""
Admin router — user management, system configuration, institution-level operations.
All endpoints require SUPER_ADMIN + MFA.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from api import models
from api.database import get_db
from api.deps import require_mfa, require_roles
from api.security import generate_totp_secret, hash_password
from api.utils.audit_chain import write_audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["Admin"])

_SUPER_ADMIN = ("SUPER_ADMIN",)


class CreateUserRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=8, max_length=100)
    roles: list[str]
    branch_code: str | None = None
    phone: str | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    roles: list[str]
    is_active: bool
    mfa_enabled: bool
    branch_code: str | None
    last_login_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class UpdateUserRequest(BaseModel):
    full_name: str | None = None
    roles: list[str] | None = None
    is_active: bool | None = None
    branch_code: str | None = None


VALID_ROLES = {
    "SUPER_ADMIN", "ADMIN", "FIELD_OFFICER", "CREDIT_MANAGER",
    "COMPLIANCE_OFFICER", "TELLER", "AUDIT_VIEWER",
}


@router.post("/users", response_model=UserResponse, status_code=201,
             summary="Create staff user (SUPER_ADMIN only)")
def create_user(
    body: CreateUserRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires SUPER_ADMIN")

    invalid = set(body.roles) - VALID_ROLES
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid roles: {invalid}")

    if db.query(models.User).filter_by(email=body.email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = models.User(
        email=body.email,
        full_name=body.full_name,
        password_hash=hash_password(body.password),
        roles=body.roles,
        branch_code=body.branch_code,
        phone=body.phone,
        is_active=True,
        mfa_enabled=False,
        created_by=current_user.id,
    )
    db.add(user)
    db.commit()

    write_audit(db, table_name="users", record_id=user.id, action="CREATE",
                actor_id=current_user.id,
                data={"email": body.email, "roles": body.roles})

    return user


@router.get("/users", response_model=list[UserResponse], summary="List staff users")
def list_users(
    is_active: bool | None = None,
    role: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_SUPER_ADMIN)),
):
    q = db.query(models.User)
    if is_active is not None:
        q = q.filter_by(is_active=is_active)
    if role:
        q = q.filter(models.User.roles.contains([role]))
    return q.offset((page - 1) * page_size).limit(page_size).all()


@router.get("/users/{user_id}", response_model=UserResponse, summary="Get staff user")
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_SUPER_ADMIN)),
):
    return _get_user_or_404(db, user_id)


@router.patch("/users/{user_id}", response_model=UserResponse, summary="Update staff user")
def update_user(
    user_id: str,
    body: UpdateUserRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires SUPER_ADMIN")

    user = _get_user_or_404(db, user_id)
    changes: dict[str, Any] = {}

    if body.full_name is not None:
        user.full_name = body.full_name
        changes["full_name"] = body.full_name
    if body.roles is not None:
        invalid = set(body.roles) - VALID_ROLES
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid roles: {invalid}")
        user.roles = body.roles
        changes["roles"] = body.roles
    if body.is_active is not None:
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.branch_code is not None:
        user.branch_code = body.branch_code
        changes["branch_code"] = body.branch_code

    db.commit()

    write_audit(db, table_name="users", record_id=user.id, action="UPDATE",
                actor_id=current_user.id, data=changes)

    return user


@router.post("/users/{user_id}/reset-password", summary="Force password reset")
def reset_password(
    user_id: str,
    new_password: str = Query(min_length=8),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires SUPER_ADMIN")

    user = _get_user_or_404(db, user_id)
    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()

    write_audit(db, table_name="users", record_id=user.id, action="PASSWORD_RESET",
                actor_id=current_user.id, data={"forced_by": current_user.email})

    return {"detail": "Password reset successfully"}


@router.delete("/users/{user_id}/deactivate", summary="Deactivate staff account")
def deactivate_user(
    user_id: str,
    reason: str = Query(min_length=10),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires SUPER_ADMIN")
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user = _get_user_or_404(db, user_id)
    user.is_active = False
    db.commit()

    write_audit(db, table_name="users", record_id=user.id, action="DEACTIVATE",
                actor_id=current_user.id, data={"reason": reason})

    return {"detail": "User deactivated"}


@router.get("/system/stats", summary="System statistics")
def system_stats(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_SUPER_ADMIN)),
):
    return {
        "customers": {
            "total": db.query(models.Customer).count(),
            "active": db.query(models.Customer).filter_by(is_active=True).count(),
            "kyc_complete": db.query(models.Customer).filter_by(kyc_status="ACTIVE").count(),
            "suspended": db.query(models.Customer).filter_by(is_suspended=True).count(),
        },
        "loans": {
            "total": db.query(models.Loan).count(),
            "active": db.query(models.Loan).filter_by(status="ACTIVE").count(),
            "disbursed": db.query(models.Loan).filter_by(status="DISBURSED").count(),
            "overdue": db.query(models.Loan).filter(models.Loan.days_past_due > 0).count(),
            "settled": db.query(models.Loan).filter_by(status="SETTLED").count(),
        },
        "savings": {
            "total_accounts": db.query(models.SavingsAccount).count(),
            "active_accounts": db.query(models.SavingsAccount).filter_by(status="ACTIVE").count(),
        },
        "compliance": {
            "open_aml_alerts": db.query(models.AMLAlert).filter_by(status="OPEN").count(),
            "total_audit_logs": db.query(models.AuditLog).count(),
        },
        "staff": {
            "total": db.query(models.User).count(),
            "active": db.query(models.User).filter_by(is_active=True).count(),
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _get_user_or_404(db: Session, user_id: str) -> models.User:
    user = db.query(models.User).filter_by(id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
