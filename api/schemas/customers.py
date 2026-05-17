"""Pydantic schemas for customer endpoints."""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, EmailStr, Field, field_validator


class CustomerCreateRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    other_names: str | None = None
    ghana_card_number: str
    phone: str
    email: EmailStr | None = None
    date_of_birth: datetime | None = None
    gender: str | None = None
    post_gps: str | None = None
    region: str | None = None
    district: str | None = None
    residential_address: str | None = None
    employer_name: str | None = None
    occupation: str | None = None
    monthly_income_ghs: Decimal | None = None
    customer_type: str = "INDIVIDUAL"
    password: str = Field(min_length=6, max_length=100)

    @field_validator("ghana_card_number")
    @classmethod
    def check_ghana_card(cls, v: str) -> str:
        from api.validators.ghana_validators import validate_ghana_card
        return validate_ghana_card(v)

    @field_validator("phone")
    @classmethod
    def check_phone(cls, v: str) -> str:
        from api.validators.ghana_validators import validate_ghana_phone
        e164, _ = validate_ghana_phone(v)
        return e164


class CustomerUpdateRequest(BaseModel):
    email: EmailStr | None = None
    residential_address: str | None = None
    employer_name: str | None = None
    occupation: str | None = None
    monthly_income_ghs: Decimal | None = None
    post_gps: str | None = None
    region: str | None = None
    district: str | None = None


class CustomerResponse(BaseModel):
    id: str
    account_number: str
    customer_type: str
    first_name: str
    last_name: str
    ghana_card_number: str
    phone_e164: str
    email: str | None
    kyc_status: str
    risk_level: str
    is_active: bool
    is_suspended: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CustomerListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[CustomerResponse]


class KYCStepRequest(BaseModel):
    step: str
    step_data: dict


class KYCStatusResponse(BaseModel):
    customer_id: str
    kyc_status: str
    current_step: str
    steps_completed: list[str]
    next_step: str | None
    kyc_completed_at: datetime | None

    model_config = {"from_attributes": True}


class BeneficialOwnerRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=255)
    ghana_card_number: str
    ownership_pct: Decimal = Field(ge=1, le=100)
    is_pep: bool = False
    nationality: str | None = None
    role: str | None = None

    @field_validator("ghana_card_number")
    @classmethod
    def check_card(cls, v: str) -> str:
        from api.validators.ghana_validators import validate_ghana_card
        return validate_ghana_card(v)


class CustomerSearchParams(BaseModel):
    q: str | None = None
    kyc_status: str | None = None
    risk_level: str | None = None
    is_active: bool | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
