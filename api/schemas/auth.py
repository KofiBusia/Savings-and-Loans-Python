"""Pydantic schemas for authentication endpoints."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator


class StaffLoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)


class MFAVerifyRequest(BaseModel):
    email: EmailStr
    totp_code: str = Field(pattern=r"^\d{6}$")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    mfa_required: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class MFASetupResponse(BaseModel):
    provisioning_uri: str
    secret: str


class CustomerLoginRequest(BaseModel):
    phone: str = Field(description="Ghana phone number (0XX or +233XX)")
    password: str = Field(min_length=6, max_length=100)


class CustomerRegisterRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    ghana_card_number: str = Field(description="Format: GHA-XXXXXXXXX-X")
    phone: str
    password: str = Field(min_length=6, max_length=100)

    @field_validator("ghana_card_number")
    @classmethod
    def check_ghana_card(cls, v: str) -> str:
        from api.validators.ghana_validators import validate_ghana_card
        return validate_ghana_card(v)


class CustomerTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    account_number: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=100)

    @field_validator("new_password")
    @classmethod
    def validate_strength(cls, v: str) -> str:
        import re
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain an uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Must contain a lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Must contain a digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Must contain a special character")
        return v


class UserMeResponse(BaseModel):
    id: str
    email: str
    full_name: str | None
    roles: list[str]
    mfa_enabled: bool
    branch_code: str | None

    model_config = {"from_attributes": True}
