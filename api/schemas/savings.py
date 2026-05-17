"""Pydantic schemas for savings endpoints."""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field


class SavingsAccountCreate(BaseModel):
    customer_id: str
    product_name: str = "Regular Savings"
    initial_deposit_ghs: Decimal = Field(default=Decimal("0"), ge=0)
    interest_rate_pa: Decimal = Field(
        default=Decimal("0.08"),
        ge=0,
        le=Decimal("0.30"),
        description="Annual interest rate e.g. 0.08 = 8%",
    )
    minimum_balance: Decimal = Field(default=Decimal("0"), ge=0)


class SavingsAccountResponse(BaseModel):
    id: str
    customer_id: str
    account_number: str
    product_name: str
    balance: Decimal
    locked_amount: Decimal
    interest_rate_pa: Decimal
    minimum_balance: Decimal
    status: str
    last_transaction_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class DepositRequest(BaseModel):
    amount_ghs: Decimal = Field(gt=0)
    channel: str = Field(default="MOBILE_MONEY")
    mno_reference: str | None = None
    narration: str | None = None


class WithdrawalRequest(BaseModel):
    amount_ghs: Decimal = Field(gt=0)
    channel: str = Field(default="MOBILE_MONEY")
    destination_account: str | None = None
    narration: str | None = None


class TransferRequest(BaseModel):
    to_account_number: str
    amount_ghs: Decimal = Field(gt=0)
    narration: str | None = None


class SavingsTransactionResponse(BaseModel):
    id: str
    reference: str
    type: str
    amount: Decimal
    balance_before: Decimal
    balance_after: Decimal
    channel: str | None
    narration: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class SavingsStatementParams(BaseModel):
    from_date: datetime | None = None
    to_date: datetime | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class SavingsStatementResponse(BaseModel):
    account_number: str
    balance: Decimal
    from_date: datetime | None
    to_date: datetime | None
    total_transactions: int
    transactions: list[SavingsTransactionResponse]
