"""
Authentication router — staff login/MFA and customer login/register.
Staff tokens: access (30 min) + refresh (7 days)
Customer tokens: access (24 h) + refresh (30 days)
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from api import models
from api.config import settings
from api.database import get_db
from api.deps import get_current_user, get_current_customer
from api.schemas.auth import (
    CustomerLoginRequest,
    CustomerRegisterRequest,
    CustomerTokenResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    PasswordChangeRequest,
    RefreshRequest,
    StaffLoginRequest,
    TokenResponse,
    UserMeResponse,
)
from api.security import (
    create_access_token,
    create_customer_access_token,
    create_customer_refresh_token,
    create_refresh_token,
    decode_token,
    generate_account_number,
    generate_totp_secret,
    get_totp_provisioning_uri,
    hash_password,
    hash_token,
    verify_password,
    verify_totp,
)
from api.utils.audit_chain import write_audit
from api.validators.ghana_validators import validate_ghana_phone

log = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


# ─── Staff Auth ────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse, summary="Staff login")
def staff_login(body: StaffLoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=body.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Account lockout — Cybersecurity Act 2020 s.34
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account locked. Try again later.",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            log.warning("account_locked email=%s", body.email)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")

    # Reset failed attempts on successful login
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    db.commit()

    mfa_required = user.mfa_enabled
    # If MFA is required, issue a short-lived token that only allows /auth/mfa/verify
    mfa_verified = not mfa_required

    access_token = create_access_token(user.id, user.roles or [], mfa_verified=mfa_verified)
    refresh_token = create_refresh_token(user.id)

    _save_refresh_token(db, user_id=user.id, token=refresh_token,
                        ip=_get_ip(request), ua=request.headers.get("user-agent"))

    write_audit(db, table_name="users", record_id=user.id, action="LOGIN",
                actor_id=user.id, actor_type="USER",
                data={"email": user.email, "mfa_required": mfa_required},
                ip_address=_get_ip(request))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        mfa_required=mfa_required,
    )


@router.post("/mfa/verify", response_model=TokenResponse, summary="Complete MFA challenge")
def verify_mfa(body: MFAVerifyRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(email=body.email).first()
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA not configured")

    if not verify_totp(user.mfa_secret, body.totp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")

    user.mfa_verified_at = datetime.utcnow()
    db.commit()

    access_token = create_access_token(user.id, user.roles or [], mfa_verified=True)
    refresh_token = create_refresh_token(user.id)
    _save_refresh_token(db, user_id=user.id, token=refresh_token,
                        ip=_get_ip(request), ua=request.headers.get("user-agent"))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        mfa_required=False,
    )


@router.post("/mfa/setup", response_model=MFASetupResponse, summary="Set up TOTP MFA")
def setup_mfa(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = generate_totp_secret()
    current_user.mfa_secret = secret
    current_user.mfa_enabled = True
    db.commit()
    return MFASetupResponse(
        provisioning_uri=get_totp_provisioning_uri(secret, current_user.email),
        secret=secret,
    )


@router.post("/refresh", response_model=TokenResponse, summary="Refresh access token")
def refresh_token(body: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Wrong token type")

    token_hash = hash_token(body.refresh_token)
    stored = db.query(models.RefreshToken).filter_by(token_hash=token_hash).first()
    if not stored or stored.revoked_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    user = db.query(models.User).filter_by(id=payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    stored.revoked_at = datetime.utcnow()  # rotate — one-time use

    new_access = create_access_token(user.id, user.roles or [], mfa_verified=bool(user.mfa_enabled))
    new_refresh = create_refresh_token(user.id)
    _save_refresh_token(db, user_id=user.id, token=new_refresh,
                        ip=_get_ip(request), ua=request.headers.get("user-agent"))
    db.commit()

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", summary="Revoke refresh token")
def logout(body: RefreshRequest, db: Session = Depends(get_db),
           current_user: models.User = Depends(get_current_user)):
    token_hash = hash_token(body.refresh_token)
    stored = db.query(models.RefreshToken).filter_by(token_hash=token_hash).first()
    if stored:
        stored.revoked_at = datetime.utcnow()
        db.commit()
    return {"detail": "Logged out"}


@router.get("/me", response_model=UserMeResponse, summary="Current user profile")
def me(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.put("/password", summary="Change staff password")
def change_password(body: PasswordChangeRequest, db: Session = Depends(get_db),
                    current_user: models.User = Depends(get_current_user)):
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")
    current_user.password_hash = hash_password(body.new_password)
    current_user.password_changed_at = datetime.utcnow()
    db.commit()
    write_audit(db, table_name="users", record_id=current_user.id, action="PASSWORD_CHANGED",
                actor_id=current_user.id, actor_type="USER", data={})
    return {"detail": "Password updated"}


# ─── Customer Auth ─────────────────────────────────────────────────────────────

@router.post("/customer/register", response_model=CustomerTokenResponse,
             summary="Register a new customer (mobile app)")
def customer_register(body: CustomerRegisterRequest, request: Request,
                      db: Session = Depends(get_db)):
    e164, mno = validate_ghana_phone(body.phone)

    if db.query(models.Customer).filter_by(ghana_card_number=body.ghana_card_number).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Ghana Card already registered")
    if db.query(models.Customer).filter_by(phone_e164=e164).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already registered")

    account_number = generate_account_number()
    customer = models.Customer(
        account_number=account_number,
        first_name=body.first_name,
        last_name=body.last_name,
        ghana_card_number=body.ghana_card_number,
        phone_e164=e164,
        mno=mno,
        password_hash=hash_password(body.password),
        kyc_status="PENDING_GHANA_CARD",
        is_active=False,  # activates after KYC completion
    )
    db.add(customer)
    db.flush()  # get ID

    savings = models.SavingsAccount(
        customer_id=customer.id,
        account_number=generate_account_number("SAV"),
        product_name="Regular Savings",
        status="PENDING_ACTIVATION",
    )
    db.add(savings)
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="REGISTER",
                actor_id=customer.id, actor_type="CUSTOMER",
                data={"account_number": account_number},
                ip_address=_get_ip(request))

    access_token = create_customer_access_token(customer.id, account_number)
    refresh_token = create_customer_refresh_token(customer.id)
    _save_refresh_token(db, customer_id=customer.id, token=refresh_token,
                        ip=_get_ip(request), ua=request.headers.get("user-agent"))
    db.commit()

    return CustomerTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=86400,  # 24 hours
        account_number=account_number,
    )


@router.post("/customer/login", response_model=CustomerTokenResponse,
             summary="Customer login (mobile app)")
def customer_login(body: CustomerLoginRequest, request: Request, db: Session = Depends(get_db)):
    e164, _ = validate_ghana_phone(body.phone)
    customer = db.query(models.Customer).filter_by(phone_e164=e164).first()

    if not customer or not verify_password(body.password, customer.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if customer.is_suspended:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Account suspended: {customer.suspension_reason}")

    access_token = create_customer_access_token(customer.id, customer.account_number)
    refresh_token = create_customer_refresh_token(customer.id)
    _save_refresh_token(db, customer_id=customer.id, token=refresh_token,
                        ip=_get_ip(request), ua=request.headers.get("user-agent"))
    db.commit()

    write_audit(db, table_name="customers", record_id=customer.id, action="LOGIN",
                actor_id=customer.id, actor_type="CUSTOMER",
                data={}, ip_address=_get_ip(request))

    return CustomerTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=86400,
        account_number=customer.account_number,
    )


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _save_refresh_token(db: Session, token: str, ip: str | None,
                        ua: str | None, user_id: str | None = None,
                        customer_id: str | None = None) -> None:
    from datetime import datetime, timedelta
    token_hash = hash_token(token)
    db.add(models.RefreshToken(
        user_id=user_id,
        customer_id=customer_id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days),
        ip_address=ip,
        user_agent=ua,
    ))


def _get_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
