"""Pydantic schemas for commission system."""
from __future__ import annotations
from datetime import datetime
from decimal import Decimal
from typing import Optional
from pydantic import BaseModel, Field


class CommissionPolicyCreate(BaseModel):
    name: str = Field(default="Default Policy", min_length=1, max_length=100)
    commission_rate: Decimal = Field(gt=0, le=Decimal("0.50"),
        description="Commission as fraction of interest. 0.05 = 5%")
    trigger_repayment: int = Field(default=6, ge=1, le=36,
        description="Commissions accrue from this repayment number onwards")
    is_active: bool = True
    applies_to_product_id: Optional[str] = None


class CommissionPolicyResponse(BaseModel):
    id: str
    name: str
    commission_rate: Decimal
    trigger_repayment: int
    is_active: bool
    applies_to_product_id: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    model_config = {"from_attributes": True}


class CommissionResponse(BaseModel):
    id: str
    officer_id: str
    loan_id: str
    repayment_id: str
    repayment_number: int
    interest_amount: Decimal
    commission_rate: Decimal
    commission_amount: Decimal
    status: str
    paid_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class CommissionSummary(BaseModel):
    officer_id: str
    officer_name: Optional[str]
    total_pending: Decimal
    total_paid: Decimal
    total_earned: Decimal
    commission_count: int


class OfficerAssignRequest(BaseModel):
    officer_id: str


class CommissionPayoutRequest(BaseModel):
    commission_ids: list[str]
    payment_reference: str
    notes: Optional[str] = None
