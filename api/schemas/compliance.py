"""Pydantic schemas for compliance endpoints."""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field


class AMLAlertResponse(BaseModel):
    id: str
    customer_id: str | None
    alert_type: str
    amount_ghs: Decimal | None
    patterns: list | None
    status: str
    risk_score: int | None
    fic_reference: str | None
    filed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AMLAlertUpdateRequest(BaseModel):
    status: str = Field(description="UNDER_REVIEW | FILED_CTR | FILED_STR | DISMISSED | ESCALATED")
    review_notes: str | None = None


class STRFilingRequest(BaseModel):
    alert_id: str
    reporting_reason: str
    narrative: str = Field(min_length=100, description="Min 100 chars — FIC requirement")
    estimated_amount_ghs: Decimal | None = None


class CTRFilingRequest(BaseModel):
    customer_id: str
    transaction_id: str
    transaction_type: str
    amount_ghs: Decimal = Field(ge=Decimal("10000"))
    transaction_date: datetime
    channel: str


class FICSubmissionResponse(BaseModel):
    fic_reference: str
    submitted_at: datetime
    status: str
    xml_preview: str | None = None


class CreditBureauSubmissionRequest(BaseModel):
    batch_date: datetime | None = None
    force_resubmit: bool = False


class CreditBureauSubmissionResponse(BaseModel):
    id: str
    batch_date: datetime
    bureau: str
    record_count: int
    status: str
    submitted_at: datetime | None

    model_config = {"from_attributes": True}


class RegulatoryReportResponse(BaseModel):
    id: str
    report_type: str
    period_start: datetime | None
    period_end: datetime | None
    submitted_at: datetime | None
    status: str
    submission_reference: str | None
    deadline: datetime | None

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    id: str
    table_name: str
    record_id: str
    action: str
    actor_id: str
    actor_type: str
    data: dict | None
    ip_address: str | None
    hash: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditChainVerifyResponse(BaseModel):
    chain_valid: bool
    total_records: int
    verified_at: datetime
    first_record_id: str | None
    last_record_id: str | None
    error: str | None = None


class ComplianceDashboardResponse(BaseModel):
    open_aml_alerts: int
    overdue_ctrs: int
    overdue_strs: int
    pending_edd_reviews: int
    credit_bureau_last_submitted: datetime | None
    audit_chain_status: str  # VALID | TAMPERED | UNVERIFIED
    upcoming_report_deadlines: list[dict]
