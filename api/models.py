"""
SQLAlchemy ORM models — Ghana Savings & Loans Platform.

Column naming follows BoG prescribed formats where mandated (L.I. 2394 Regulation 8).
All monetary amounts stored as NUMERIC(18,2) — Decimal precision, no floating point.
All timestamps stored as TIMESTAMP WITH TIME ZONE (UTC).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import JSON as _JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from api.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.utcnow()


# ──────────────────────────────────────────────────────────────────────────────
# STAFF USERS
# ──────────────────────────────────────────────────────────────────────────────

class User(Base):
    """Staff users — field officers, compliance officers, admin, credit managers."""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    phone = Column(String(20))
    roles = Column(_JSON, nullable=False, default=list)
    # Roles: SUPER_ADMIN, ADMIN, FIELD_OFFICER, CREDIT_MANAGER,
    #        COMPLIANCE_OFFICER, TELLER, AUDIT_VIEWER

    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(64))  # TOTP secret — encrypted at rest in production
    mfa_verified_at = Column(DateTime(timezone=True))

    is_active = Column(Boolean, default=True, nullable=False)
    branch_code = Column(String(20))
    last_login_at = Column(DateTime(timezone=True))
    password_changed_at = Column(DateTime(timezone=True))
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)


# ──────────────────────────────────────────────────────────────────────────────
# CUSTOMERS
# ──────────────────────────────────────────────────────────────────────────────

class Customer(Base):
    """
    Individual or SME customer.
    Ghana Card number is the sole identity anchor (AML Act 1044 s.18).
    """
    __tablename__ = "customers"
    __table_args__ = (
        UniqueConstraint("ghana_card_number", name="uq_customers_ghana_card"),
        UniqueConstraint("phone_e164", name="uq_customers_phone"),
        UniqueConstraint("account_number", name="uq_customers_account_number"),
    )

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    account_number = Column(String(20), nullable=False, index=True)
    customer_type = Column(String(20), nullable=False, default="INDIVIDUAL")
    # INDIVIDUAL | SME | COOPERATIVE | NGO

    # Identity (AML Act 1044 s.18)
    ghana_card_number = Column(String(20), nullable=False, index=True)
    ghana_card_verified = Column(Boolean, default=False, nullable=False)
    ghana_card_verified_at = Column(DateTime(timezone=True))
    ghana_card_expiry = Column(DateTime(timezone=True))

    # Personal
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    other_names = Column(String(100))
    date_of_birth = Column(DateTime(timezone=True))
    gender = Column(String(10))
    nationality = Column(String(50), default="Ghanaian")

    # Contact
    phone_e164 = Column(String(20), nullable=False, index=True)
    mno = Column(String(30))   # MTN | Telecel | AirtelTigo
    email = Column(String(255), index=True)
    password_hash = Column(String(255), nullable=False)  # customer app login

    # Address (Ghana Post GPS — Data Protection Act 843 s.25)
    post_gps = Column(String(20))
    digital_address = Column(String(100))
    region = Column(String(50))
    district = Column(String(100))
    residential_address = Column(Text)
    employer_name = Column(String(255))
    occupation = Column(String(100))
    monthly_income_ghs = Column(Numeric(18, 2))

    # Risk & Compliance
    risk_level = Column(String(20), default="LOW")  # LOW | MEDIUM | HIGH
    pep_match = Column(Boolean, default=False, nullable=False)
    pep_match_details = Column(JSON)
    sanctions_match = Column(Boolean, default=False, nullable=False)
    kyc_status = Column(String(40), nullable=False, default="PENDING_GHANA_CARD")
    kyc_completed_at = Column(DateTime(timezone=True))
    cdd_review_due_at = Column(DateTime(timezone=True))
    edd_required = Column(Boolean, default=False, nullable=False)
    edd_completed_at = Column(DateTime(timezone=True))

    # Account status
    is_active = Column(Boolean, default=False, nullable=False)
    is_suspended = Column(Boolean, default=False, nullable=False)
    suspension_reason = Column(Text)
    suspended_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)
    onboarded_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)

    # Relationships
    savings_accounts = relationship("SavingsAccount", back_populates="customer", lazy="select")
    loans = relationship("Loan", back_populates="customer", lazy="select")
    kyc_records = relationship("KYCRecord", back_populates="customer", lazy="select")
    beneficial_owners = relationship("BeneficialOwner", back_populates="customer", lazy="select")
    device_bindings = relationship("DeviceBinding", back_populates="customer", lazy="select")


class KYCRecord(Base):
    """Per-step KYC state machine audit trail (12-step FSM)."""
    __tablename__ = "kyc_records"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=False, index=True)
    step = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)  # PENDING | COMPLETED | FAILED | SKIPPED
    step_data = Column(JSON)                      # Documents, scores, decisions per step
    completed_at = Column(DateTime(timezone=True))
    completed_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    failure_reason = Column(Text)
    hash = Column(String(64))                     # SHA-256 of step record

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    customer = relationship("Customer", back_populates="kyc_records")


class BeneficialOwner(Base):
    """SME beneficial owners — AML Act 1044 s.22, 25% ownership threshold."""
    __tablename__ = "beneficial_owners"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    ghana_card_number = Column(String(20), nullable=False)
    ownership_pct = Column(Numeric(5, 2), nullable=False)
    is_pep = Column(Boolean, default=False, nullable=False)
    nationality = Column(String(50))
    role = Column(String(100))

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    customer = relationship("Customer", back_populates="beneficial_owners")


class DeviceBinding(Base):
    """Customer mobile device registrations — Cybersecurity Act 2020 s.34."""
    __tablename__ = "device_bindings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=False, index=True)
    device_id = Column(String(255), nullable=False)
    device_name = Column(String(255))
    platform = Column(String(20))  # ios | android
    push_token = Column(String(500))
    is_trusted = Column(Boolean, default=False, nullable=False)
    bound_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    last_seen_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))

    customer = relationship("Customer", back_populates="device_bindings")


# ──────────────────────────────────────────────────────────────────────────────
# SAVINGS
# ──────────────────────────────────────────────────────────────────────────────

class SavingsAccount(Base):
    __tablename__ = "savings_accounts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=False, index=True)
    account_number = Column(String(20), unique=True, nullable=False, index=True)
    product_name = Column(String(100), nullable=False, default="Regular Savings")
    currency = Column(String(3), nullable=False, default="GHS")

    balance = Column(Numeric(18, 2), nullable=False, default=0)
    locked_amount = Column(Numeric(18, 2), nullable=False, default=0)  # held as collateral
    interest_rate_pa = Column(Numeric(5, 4), nullable=False, default=0)  # e.g. 0.0800 = 8% p.a.
    minimum_balance = Column(Numeric(18, 2), nullable=False, default=0)

    status = Column(String(20), nullable=False, default="PENDING_ACTIVATION")
    # PENDING_ACTIVATION | ACTIVE | DORMANT | FROZEN | CLOSED

    dormancy_threshold_days = Column(Integer, default=180)
    last_transaction_at = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)

    customer = relationship("Customer", back_populates="savings_accounts")
    transactions = relationship("SavingsTransaction", back_populates="account", lazy="select")


class SavingsTransaction(Base):
    __tablename__ = "savings_transactions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    account_id = Column(UUID(as_uuid=False), ForeignKey("savings_accounts.id"), nullable=False, index=True)
    reference = Column(String(100), unique=True, nullable=False, index=True)

    type = Column(String(30), nullable=False)
    # DEPOSIT | WITHDRAWAL | INTEREST_CREDIT | FEE_DEBIT | TRANSFER_IN | TRANSFER_OUT | REVERSAL

    amount = Column(Numeric(18, 2), nullable=False)
    balance_before = Column(Numeric(18, 2), nullable=False)
    balance_after = Column(Numeric(18, 2), nullable=False)
    currency = Column(String(3), nullable=False, default="GHS")

    channel = Column(String(30))  # MOBILE_MONEY | BANK_TRANSFER | CASH | GHIPSS
    mno_reference = Column(String(100))        # GhIPSS/MoMo reference
    narration = Column(String(500))

    # AML flags
    ctr_required = Column(Boolean, default=False, nullable=False)
    ctr_filed_at = Column(DateTime(timezone=True))
    str_required = Column(Boolean, default=False, nullable=False)
    str_filed_at = Column(DateTime(timezone=True))

    processed_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    reversed_at = Column(DateTime(timezone=True))
    reversal_reason = Column(Text)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    account = relationship("SavingsAccount", back_populates="transactions")


# ──────────────────────────────────────────────────────────────────────────────
# LOANS
# ──────────────────────────────────────────────────────────────────────────────

class LoanProduct(Base):
    """Loan product templates — reviewed by Credit Manager, approved by Super Admin."""
    __tablename__ = "loan_products"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)

    # Interest — SIMPLE ONLY. Compound is a criminal offence under DCD 2025 Clause 14.
    annual_interest_rate = Column(Numeric(5, 4), nullable=False)   # e.g. 0.2800 = 28% p.a.
    processing_fee_pct = Column(Numeric(5, 4), nullable=False, default=0)
    insurance_fee_pct = Column(Numeric(5, 4), nullable=False, default=0)
    late_payment_fee_pct = Column(Numeric(5, 4), nullable=False, default=0)  # per month overdue

    min_amount_ghs = Column(Numeric(18, 2), nullable=False)
    max_amount_ghs = Column(Numeric(18, 2), nullable=False)
    min_tenure_months = Column(Integer, nullable=False)
    max_tenure_months = Column(Integer, nullable=False)

    requires_collateral = Column(Boolean, default=False, nullable=False)
    requires_guarantor = Column(Boolean, default=False, nullable=False)
    eligible_customer_types = Column(_JSON, nullable=False, default=list)
    minimum_kyc_status = Column(String(40), nullable=False, default="ACTIVE")

    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)

    loans = relationship("Loan", back_populates="product", lazy="select")


class Loan(Base):
    """
    Loan record. Amount, schedule, and repayments computed using
    SimpleInterestCalculator — compound interest is blocked by build gate.
    """
    __tablename__ = "loans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    loan_number = Column(String(30), unique=True, nullable=False, index=True)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=False, index=True)
    product_id = Column(UUID(as_uuid=False), ForeignKey("loan_products.id"), nullable=False)

    # Amounts
    principal_ghs = Column(Numeric(18, 2), nullable=False)
    annual_interest_rate = Column(Numeric(5, 4), nullable=False)  # snapshot from product
    tenure_months = Column(Integer, nullable=False)
    processing_fee_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    insurance_fee_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    total_interest_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    total_repayable_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    monthly_instalment_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    apr = Column(Numeric(7, 4))  # Annual Percentage Rate — DCD 2025 Clause 11 disclosure

    # Status lifecycle
    status = Column(String(30), nullable=False, default="APPLICATION")
    # APPLICATION | CREDIT_CHECK | DOCUMENT_COLLECTION | CREDIT_COMMITTEE |
    # APPROVED | REJECTED | DISBURSED | ACTIVE | OVERDUE | RESTRUCTURED |
    # WRITTEN_OFF | SETTLED | CANCELLED

    # Dates
    applied_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    approved_at = Column(DateTime(timezone=True))
    disbursed_at = Column(DateTime(timezone=True))
    first_repayment_date = Column(DateTime(timezone=True))
    maturity_date = Column(DateTime(timezone=True))
    settled_at = Column(DateTime(timezone=True))
    next_due_date = Column(DateTime(timezone=True))

    # DCD 2025 Clause 8 — pre-agreement display tracking
    pre_agreement_displayed_at = Column(DateTime(timezone=True))
    pre_agreement_accepted_at = Column(DateTime(timezone=True))
    pre_agreement_display_seconds = Column(Integer)

    # DCD 2025 Clause 11 — cooling-off period
    cooling_off_expires_at = Column(DateTime(timezone=True))
    cooling_off_exercised = Column(Boolean, default=False, nullable=False)

    # Disbursement
    disbursement_channel = Column(String(30))  # GHIPSS | BANK_TRANSFER | CASH
    disbursement_reference = Column(String(100))
    disbursement_account = Column(String(30))  # MoMo number or bank account

    # Officers
    applied_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))   # field officer
    approved_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    rejected_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    rejection_reason = Column(Text)
    disbursed_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))

    # Risk
    credit_score = Column(Integer)
    bureau_checked_at = Column(DateTime(timezone=True))
    dti_ratio = Column(Numeric(5, 4))  # Debt-to-Income

    # Repayment tracking
    amount_paid_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    outstanding_ghs = Column(Numeric(18, 2), nullable=False, default=0)
    days_past_due = Column(Integer, default=0, nullable=False)
    arrears_amount_ghs = Column(Numeric(18, 2), nullable=False, default=0)

    # Collateral
    schedule_json = Column(JSON)           # full repayment schedule snapshot

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)

    customer = relationship("Customer", back_populates="loans")
    product = relationship("LoanProduct", back_populates="loans")
    repayments = relationship("LoanRepayment", back_populates="loan", lazy="select")
    collateral = relationship("CollateralRegistry", back_populates="loan", lazy="select")


class LoanRepayment(Base):
    """Each individual repayment received against a loan."""
    __tablename__ = "loan_repayments"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    loan_id = Column(UUID(as_uuid=False), ForeignKey("loans.id"), nullable=False, index=True)
    reference = Column(String(100), unique=True, nullable=False, index=True)

    instalment_number = Column(Integer)
    due_date = Column(DateTime(timezone=True))
    paid_date = Column(DateTime(timezone=True))

    principal_component = Column(Numeric(18, 2), nullable=False, default=0)
    interest_component = Column(Numeric(18, 2), nullable=False, default=0)
    fee_component = Column(Numeric(18, 2), nullable=False, default=0)
    penalty_component = Column(Numeric(18, 2), nullable=False, default=0)
    total_amount = Column(Numeric(18, 2), nullable=False)

    channel = Column(String(30))
    mno_reference = Column(String(100))
    collected_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))

    # AML
    ctr_required = Column(Boolean, default=False, nullable=False)
    str_required = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    loan = relationship("Loan", back_populates="repayments")


class CollateralRegistry(Base):
    """
    Collateral pledged against a loan.
    Registered with Collateral Registry of Ghana (Borrowers & Lenders Act 2020, Part IV).
    """
    __tablename__ = "collateral_registry"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    loan_id = Column(UUID(as_uuid=False), ForeignKey("loans.id"), nullable=False, index=True)
    collateral_type = Column(String(50), nullable=False)
    # LAND_TITLE | VEHICLE | EQUIPMENT | SAVINGS_ACCOUNT | STOCKS | PERSONAL_PROPERTY

    description = Column(Text, nullable=False)
    estimated_value_ghs = Column(Numeric(18, 2), nullable=False)
    forced_sale_value_ghs = Column(Numeric(18, 2))

    # Registry reference
    collateral_registry_number = Column(String(100), index=True)
    registered_at = Column(DateTime(timezone=True))
    registry_certificate_url = Column(String(500))

    valuation_date = Column(DateTime(timezone=True))
    valuator_name = Column(String(255))
    status = Column(String(20), default="ACTIVE")  # ACTIVE | RELEASED | FORECLOSED

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    loan = relationship("Loan", back_populates="collateral")


# ──────────────────────────────────────────────────────────────────────────────
# COMPLIANCE
# ──────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Immutable SHA-256 hash-chained audit log.
    Each record links to the previous via previous_hash (Cybersecurity Act 2020 s.34).
    DO NOT UPDATE OR DELETE rows — use verify_chain() to detect tampering.
    """
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    table_name = Column(String(100), nullable=False, index=True)
    record_id = Column(String(100), nullable=False, index=True)
    action = Column(String(50), nullable=False)  # CREATE | UPDATE | DELETE | APPROVE | DISBURSE | etc.
    actor_id = Column(String(100), nullable=False, index=True)
    actor_type = Column(String(20), nullable=False, default="USER")  # USER | CUSTOMER | SYSTEM
    data = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    previous_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False, index=True)


class AMLAlert(Base):
    """AML/CFT alerts — AML Act 2020 (Act 1044) ss.22/36."""
    __tablename__ = "aml_alerts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=True, index=True)
    transaction_id = Column(String(100), index=True)
    transaction_type = Column(String(20))  # SAVINGS | LOAN_REPAYMENT | DISBURSEMENT

    alert_type = Column(String(30), nullable=False)
    # CTR | STR | STRUCTURING | RAPID_MOVEMENT | GEOGRAPHIC_ANOMALY | PEP_TRANSACTION

    amount_ghs = Column(Numeric(18, 2))
    patterns = Column(JSON)          # list of SuspiciousPattern dicts
    risk_score = Column(Integer)

    status = Column(String(30), nullable=False, default="OPEN")
    # OPEN | UNDER_REVIEW | FILED_CTR | FILED_STR | DISMISSED | ESCALATED

    assigned_to = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    reviewed_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    reviewed_at = Column(DateTime(timezone=True))
    review_notes = Column(Text)

    fic_reference = Column(String(100))    # returned by FIC after submission
    filed_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)


class RegulatoryReport(Base):
    """BoG / FIC regulatory submissions tracking."""
    __tablename__ = "regulatory_reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    report_type = Column(String(50), nullable=False, index=True)
    # CTR | STR | PRUDENTIAL_RETURN | CREDIT_BUREAU | CREDIT_REGISTRY | FIC_GOAML

    period_start = Column(DateTime(timezone=True))
    period_end = Column(DateTime(timezone=True))
    submitted_at = Column(DateTime(timezone=True))
    submitted_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    submission_reference = Column(String(200))
    status = Column(String(30), nullable=False, default="DRAFT")
    # DRAFT | SUBMITTED | ACKNOWLEDGED | ACCEPTED | REJECTED | OVERDUE

    deadline = Column(DateTime(timezone=True))
    content = Column(JSON)
    submission_payload = Column(Text)    # raw XML/JSON sent
    response_payload = Column(Text)      # raw response from regulator
    error_detail = Column(Text)

    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_now, onupdate=_now)


class CreditBureauSubmission(Base):
    """
    Daily credit bureau submissions to XDS, D&B Ghana, MyCredit.
    L.I. 2394 Regulation 8.
    """
    __tablename__ = "credit_bureau_submissions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    batch_date = Column(DateTime(timezone=True), nullable=False, index=True)
    bureau = Column(String(30), nullable=False)  # XDS | DB_GHANA | MY_CREDIT
    record_count = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="PENDING")
    submitted_at = Column(DateTime(timezone=True))
    response = Column(JSON)
    error = Column(Text)
    submitted_by = Column(UUID(as_uuid=False), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


class SanctionsList(Base):
    """
    Local cache of international sanctions/PEP lists.
    Updated via scheduled job — AML Act 1044 s.18(4).
    """
    __tablename__ = "sanctions_list"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    list_type = Column(String(30), nullable=False, index=True)
    # UN_CONSOLIDATED | OFAC_SDN | EU_CONSOLIDATED | BOG_PEP | LOCAL_BLACKLIST

    full_name = Column(String(500), nullable=False, index=True)
    aliases = Column(_JSON)
    date_of_birth = Column(String(20))
    nationality = Column(String(100))
    id_numbers = Column(_JSON)
    designation = Column(Text)
    listed_on = Column(DateTime(timezone=True))
    delisted_on = Column(DateTime(timezone=True))
    list_source_url = Column(String(500))
    is_active = Column(Boolean, default=True, nullable=False)

    synced_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)


class RefreshToken(Base):
    """JWT refresh token store — enables server-side revocation."""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    customer_id = Column(UUID(as_uuid=False), ForeignKey("customers.id"), nullable=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 of token
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
