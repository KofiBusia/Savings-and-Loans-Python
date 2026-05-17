"""
Security utilities — password hashing, JWT tokens, TOTP MFA.
Cybersecurity Act 2020 (Act 1038) s.34 — strong authentication required.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Literal

import pyotp
from jose import JWTError, jwt
from passlib.context import CryptContext

from api.config import settings

# ─── Password Hashing ─────────────────────────────────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)


def hash_token(token: str) -> str:
    """SHA-256 digest of a token — used for DB storage of refresh tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


# ─── JWT Tokens ───────────────────────────────────────────────────────────────

def _create_token(
    subject: str,
    token_type: Literal["access", "refresh", "customer_access", "customer_refresh"],
    extra_claims: dict[str, Any] | None = None,
    expire_delta: timedelta | None = None,
) -> str:
    if expire_delta is None:
        if token_type in ("access", "customer_access"):
            expire_delta = timedelta(minutes=settings.access_token_expire_minutes)
        else:
            expire_delta = timedelta(days=settings.refresh_token_expire_days)

    now = datetime.utcnow()
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + expire_delta,
        "type": token_type,
        "jti": secrets.token_urlsafe(16),  # unique per token — enables revocation check
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(user_id: str, roles: list[str], mfa_verified: bool = False) -> str:
    return _create_token(
        subject=user_id,
        token_type="access",
        extra_claims={"roles": roles, "mfa": mfa_verified},
    )


def create_refresh_token(user_id: str) -> str:
    return _create_token(subject=user_id, token_type="refresh")


def create_customer_access_token(customer_id: str, account_number: str) -> str:
    return _create_token(
        subject=customer_id,
        token_type="customer_access",
        extra_claims={"acct": account_number},
    )


def create_customer_refresh_token(customer_id: str) -> str:
    return _create_token(subject=customer_id, token_type="customer_refresh")


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT. Raises JWTError if invalid/expired.
    Callers must check the 'type' claim to prevent token substitution attacks.
    """
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


# ─── TOTP MFA (RFC 6238) ─────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_provisioning_uri(secret: str, user_email: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=user_email,
        issuer_name=settings.mfa_totp_issuer,
    )


def verify_totp(secret: str, token: str) -> bool:
    """Allow ±1 window (30s) to accommodate clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


# ─── Account Number Generation ────────────────────────────────────────────────

def generate_account_number(prefix: str = "GSL") -> str:
    """
    Format: GSL-YYYYMMDD-XXXXXX (14 chars excl hyphens).
    Use database-level unique constraint to handle the rare collision.
    """
    today = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.randbelow(10 ** 6)
    return f"{prefix}{today}{suffix:06d}"


def generate_loan_number() -> str:
    today = datetime.utcnow().strftime("%Y%m%d")
    suffix = secrets.randbelow(10 ** 5)
    return f"LN{today}{suffix:05d}"


def generate_reference() -> str:
    return secrets.token_urlsafe(16).upper()[:20]
