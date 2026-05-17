"""Pydantic schemas for loan endpoints."""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator


class LoanProductCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None
    annual_interest_rate: Decimal = Field(gt=0, le=Decimal("0.60"),
        description="Max 60% p.a. — BoG cap. DCD 2025 Clause 14.")
    processing_fee_pct: Decimal = Field(default=Decimal("0"), ge=0, le=Decimal("0.10"))
    insurance_fee_pct: Decimal = Field(default=Decimal("0"), ge=0, le=Decimal("0.05"))
    late_payment_fee_pct: Decimal = Field(default=Decimal("0.02"), ge=0, le=Decimal("0.05"))
    min_amount_ghs: Decimal = Field(gt=0)
    max_amount_ghs: Decimal = Field(gt=0)
    min_tenure_months: int = Field(ge=1)
    max_tenure_months: int = Field(ge=1, le=120)
    requires_collateral: bool = False
    requires_guarantor: bool = False
    eligible_customer_types: list[str] = ["INDIVIDUAL"]
    minimum_kyc_status: str = "ACTIVE"
    savings_ratio: Decimal = Field(default=Decimal("0.70"), gt=0, le=Decimal("1.0"),
        description="Max loan as fraction of savings balance. 0.70 = 70%")
    collateral_ratio: Decimal = Field(default=Decimal("0.50"), gt=0, le=Decimal("1.0"),
        description="Max loan as fraction of collateral value. 0.50 = 50%")


class LoanProductResponse(BaseModel):
    id: str
    name: str
    annual_interest_rate: Decimal
    processing_fee_pct: Decimal
    min_amount_ghs: Decimal
    max_amount_ghs: Decimal
    min_tenure_months: int
    max_tenure_months: int
    requires_collateral: bool
    is_active: bool
    savings_ratio: Decimal
    collateral_ratio: Decimal

    model_config = {"from_attributes": True}


class LoanApplicationRequest(BaseModel):
    customer_id: str
    product_id: str
    principal_ghs: Decimal = Field(gt=0)
    tenure_months: int = Field(ge=1, le=120)
    disbursement_channel: str = Field(default="GHIPSS")
    disbursement_account: str = Field(description="MoMo number or bank account")
    notes: str | None = None


class LoanScheduleInstalment(BaseModel):
    instalment_number: int
    due_date: str
    principal: Decimal
    interest: Decimal
    total: Decimal
    balance_after: Decimal


class LoanQuoteResponse(BaseModel):
    principal_ghs: Decimal
    annual_interest_rate: Decimal
    tenure_months: int
    total_interest_ghs: Decimal
    processing_fee_ghs: Decimal
    insurance_fee_ghs: Decimal
    total_repayable_ghs: Decimal
    monthly_instalment_ghs: Decimal
    apr: Decimal
    schedule: list[LoanScheduleInstalment]
    warning: str = (
        "This loan uses SIMPLE interest only. "
        "No compound interest is charged — DCD 2025 Clause 14."
    )


class LoanResponse(BaseModel):
    id: str
    loan_number: str
    customer_id: str
    product_id: str
    principal_ghs: Decimal
    annual_interest_rate: Decimal
    tenure_months: int
    total_interest_ghs: Decimal
    total_repayable_ghs: Decimal
    monthly_instalment_ghs: Decimal
    apr: Decimal | None
    status: str
    applied_at: datetime
    approved_at: datetime | None
    disbursed_at: datetime | None
    maturity_date: datetime | None
    next_due_date: datetime | None
    amount_paid_ghs: Decimal
    outstanding_ghs: Decimal
    days_past_due: int
    created_at: datetime

    model_config = {"from_attributes": True}


class LoanApprovalRequest(BaseModel):
    approved: bool
    notes: str | None = None
    rejection_reason: str | None = None


class LoanDisbursementRequest(BaseModel):
    disbursement_channel: str = "GHIPSS"
    disbursement_account: str
    confirm: bool = Field(..., description="Must be true to confirm disbursement")


class LoanRepaymentRequest(BaseModel):
    amount_ghs: Decimal = Field(gt=0)
    channel: str = "GHIPSS"
    mno_reference: str | None = None
    notes: str | None = None


class LoanRepaymentResponse(BaseModel):
    id: str
    loan_id: str
    reference: str
    total_amount: Decimal
    principal_component: Decimal
    interest_component: Decimal
    fee_component: Decimal
    channel: str
    created_at: datetime

    model_config = {"from_attributes": True}


class CollateralRequest(BaseModel):
    collateral_type: str
    description: str
    estimated_value_ghs: Decimal = Field(gt=0)
    forced_sale_value_ghs: Decimal | None = None
    valuation_date: datetime | None = None
    valuator_name: str | None = None


class LoanListParams(BaseModel):
    customer_id: str | None = None
    status: str | None = None
    product_id: str | None = None
    overdue_only: bool = False
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class LoanEligibilityResponse(BaseModel):
    savings_balance: Decimal
    savings_ratio: Decimal
    max_savings_loan: Decimal
    collateral_value_ghs: Decimal
    collateral_ratio: Decimal
    max_collateral_loan: Decimal
    effective_max: Decimal
    product_max: Decimal | None
    final_max: Decimal | None
    note: str
