"""
AML Compliance Engine
Regulatory anchors:
  - AML Act 2020 (Act 1044): CTR, STR, PEP screening, record keeping
  - Financial Intelligence Centre Act 2012 (Act 831): FIC reporting

CTR threshold: GHS 10,000 per single transaction (BoG AML Directive 2023)
STR: Any transaction or pattern deemed suspicious regardless of amount
Submission: FIC-prescribed XML format within prescribed timelines
  - STR: within 3 working days of suspicion
  - CTR: within 5 working days of transaction
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
from xml.etree import ElementTree as ET

from sqlalchemy.orm import Session


# ─── Constants ────────────────────────────────────────────────────────────────

CTR_THRESHOLD_GHS = Decimal("10000.00")
STR_FILING_DEADLINE_WORKING_DAYS = 3
CTR_FILING_DEADLINE_WORKING_DAYS = 5

# Structuring threshold — rapid multiple transactions to avoid CTR
STRUCTURING_WINDOW_HOURS = 24
STRUCTURING_MAX_TRANSACTIONS = 3
STRUCTURING_COMBINED_THRESHOLD = CTR_THRESHOLD_GHS * Decimal("0.9")   # 90% of threshold


# ─── Report Types ─────────────────────────────────────────────────────────────

class AMLReportType(str, Enum):
    CTR = "CTR"     # Currency Transaction Report
    STR = "STR"     # Suspicious Transaction Report


class AMLAlertStatus(str, Enum):
    PENDING    = "PENDING"
    UNDER_REVIEW = "UNDER_REVIEW"
    FILED      = "FILED"
    DISMISSED  = "DISMISSED"


# ─── Suspicious Pattern Detectors ────────────────────────────────────────────

@dataclass
class SuspiciousPattern:
    code: str
    description: str
    risk_score: int        # 1–100


def detect_suspicious_patterns(
    customer_id: str,
    current_tx: dict[str, Any],
    recent_transactions: list[dict[str, Any]],
) -> list[SuspiciousPattern]:
    """Detect suspicious transaction patterns per AML Act 1044 Schedule 2."""
    patterns: list[SuspiciousPattern] = []
    amount = Decimal(str(current_tx.get("amount", 0)))

    # 1. Structuring — multiple small transactions just below CTR threshold
    recent_total = sum(
        Decimal(str(t["amount"])) for t in recent_transactions
        if t.get("customer_id") == customer_id
        and t.get("type") in ("DEPOSIT", "LOAN_DISBURSEMENT")
    )
    if len(recent_transactions) >= STRUCTURING_MAX_TRANSACTIONS and \
       (recent_total + amount) >= STRUCTURING_COMBINED_THRESHOLD:
        patterns.append(SuspiciousPattern(
            code="STRUCTURING",
            description=(
                f"Possible structuring: {len(recent_transactions)} transactions "
                f"totalling GHS {recent_total + amount:,.2f} within {STRUCTURING_WINDOW_HOURS}h, "
                "approaching CTR threshold."
            ),
            risk_score=85,
        ))

    # 2. Round-number large transaction
    if amount >= Decimal("5000") and amount % Decimal("1000") == 0:
        patterns.append(SuspiciousPattern(
            code="ROUND_AMOUNT",
            description=f"Round-number transaction of GHS {amount:,.0f}.",
            risk_score=30,
        ))

    # 3. Rapid in-out (same day large deposit followed by withdrawal)
    today_deposits = [
        t for t in recent_transactions
        if t.get("type") == "DEPOSIT" and
        t.get("date", "") == date.today().isoformat()
    ]
    today_withdrawals = [
        t for t in recent_transactions
        if t.get("type") == "WITHDRAWAL" and
        t.get("date", "") == date.today().isoformat()
    ]
    if today_deposits and today_withdrawals:
        dep_total = sum(Decimal(str(t["amount"])) for t in today_deposits)
        if dep_total >= Decimal("5000"):
            patterns.append(SuspiciousPattern(
                code="RAPID_IN_OUT",
                description=(
                    f"Same-day in-and-out: GHS {dep_total:,.2f} deposited "
                    f"and withdrawal attempted on {date.today()}."
                ),
                risk_score=70,
            ))

    # 4. Geographic anomaly (different region from KYC address)
    if current_tx.get("gps_region") and current_tx.get("kyc_region"):
        if current_tx["gps_region"] != current_tx["kyc_region"]:
            patterns.append(SuspiciousPattern(
                code="GEOGRAPHIC_ANOMALY",
                description=(
                    f"Transaction from {current_tx['gps_region']} "
                    f"but KYC address is {current_tx['kyc_region']}."
                ),
                risk_score=40,
            ))

    return patterns


# ─── CTR Generation ───────────────────────────────────────────────────────────

def should_file_ctr(amount: Decimal) -> bool:
    """Return True if transaction amount triggers CTR obligation."""
    return amount >= CTR_THRESHOLD_GHS


def generate_ctr_xml(
    *,
    institution_code: str,
    bog_licence: str,
    customer: dict[str, Any],
    transaction: dict[str, Any],
    reporting_officer: str,
) -> str:
    """Generate FIC-prescribed CTR XML.

    Returns UTF-8 XML string ready for submission to FIC portal.
    Schema: FIC CTR XML Schema v2.1 (2023)
    """
    ref = f"CTR-{uuid.uuid4().hex[:8].upper()}"
    root = ET.Element("CurrencyTransactionReport")
    root.set("xmlns", "http://fic.gov.gh/schemas/ctr/v2")
    root.set("version", "2.1")

    # Header
    hdr = ET.SubElement(root, "ReportHeader")
    ET.SubElement(hdr, "ReportReference").text = ref
    ET.SubElement(hdr, "ReportingDate").text = date.today().isoformat()
    ET.SubElement(hdr, "InstitutionCode").text = institution_code
    ET.SubElement(hdr, "BoGLicenceNumber").text = bog_licence
    ET.SubElement(hdr, "ReportingOfficer").text = reporting_officer
    ET.SubElement(hdr, "SubmissionDeadline").text = (
        date.today() + timedelta(days=CTR_FILING_DEADLINE_WORKING_DAYS)
    ).isoformat()

    # Subject (customer)
    subj = ET.SubElement(root, "Subject")
    ET.SubElement(subj, "SubjectType").text = "INDIVIDUAL"
    ET.SubElement(subj, "FullName").text = (
        f"{customer.get('first_name', '')} {customer.get('last_name', '')}"
    )
    ET.SubElement(subj, "GhanaCardNumber").text = customer.get("ghana_card_number", "")
    ET.SubElement(subj, "PhoneNumber").text = customer.get("phone_number", "")
    ET.SubElement(subj, "Address").text = customer.get("street_address", "")
    ET.SubElement(subj, "Region").text = customer.get("region", "")
    ET.SubElement(subj, "AccountNumber").text = customer.get("account_number", "")

    # Transaction
    tx = ET.SubElement(root, "Transaction")
    ET.SubElement(tx, "TransactionDate").text = transaction.get("date", "")
    ET.SubElement(tx, "TransactionType").text = transaction.get("type", "")
    ET.SubElement(tx, "Amount").text = str(transaction.get("amount", ""))
    ET.SubElement(tx, "Currency").text = "GHS"
    ET.SubElement(tx, "PaymentMethod").text = transaction.get("method", "")
    ET.SubElement(tx, "Reference").text = transaction.get("reference", "")
    ET.SubElement(tx, "BranchCode").text = transaction.get("branch_code", "")

    return ET.tostring(root, encoding="unicode", xml_declaration=False)


# ─── STR Generation ───────────────────────────────────────────────────────────

def generate_str_xml(
    *,
    institution_code: str,
    bog_licence: str,
    customer: dict[str, Any],
    transactions: list[dict[str, Any]],
    suspicion_basis: str,
    patterns: list[SuspiciousPattern],
    reporting_officer: str,
) -> str:
    """Generate FIC-prescribed STR XML.

    Returns UTF-8 XML string ready for submission to FIC portal.
    Schema: FIC STR XML Schema v3.0 (2023)
    Deadline: 3 working days from date of suspicion.
    """
    ref = f"STR-{uuid.uuid4().hex[:8].upper()}"
    root = ET.Element("SuspiciousTransactionReport")
    root.set("xmlns", "http://fic.gov.gh/schemas/str/v3")
    root.set("version", "3.0")

    hdr = ET.SubElement(root, "ReportHeader")
    ET.SubElement(hdr, "ReportReference").text = ref
    ET.SubElement(hdr, "ReportingDate").text = date.today().isoformat()
    ET.SubElement(hdr, "InstitutionCode").text = institution_code
    ET.SubElement(hdr, "BoGLicenceNumber").text = bog_licence
    ET.SubElement(hdr, "ReportingOfficer").text = reporting_officer
    ET.SubElement(hdr, "SubmissionDeadline").text = (
        date.today() + timedelta(days=STR_FILING_DEADLINE_WORKING_DAYS)
    ).isoformat()

    subj = ET.SubElement(root, "Subject")
    ET.SubElement(subj, "FullName").text = (
        f"{customer.get('first_name', '')} {customer.get('last_name', '')}"
    )
    ET.SubElement(subj, "GhanaCardNumber").text = customer.get("ghana_card_number", "")
    ET.SubElement(subj, "PhoneNumber").text = customer.get("phone_number", "")
    ET.SubElement(subj, "AccountNumber").text = customer.get("account_number", "")
    ET.SubElement(subj, "RiskClass").text = customer.get("risk_class", "UNKNOWN")
    ET.SubElement(subj, "IsPEP").text = str(customer.get("is_pep", False)).lower()

    basis = ET.SubElement(root, "SuspicionBasis")
    ET.SubElement(basis, "Narrative").text = suspicion_basis
    pats = ET.SubElement(basis, "DetectedPatterns")
    for p in patterns:
        pat = ET.SubElement(pats, "Pattern")
        ET.SubElement(pat, "Code").text = p.code
        ET.SubElement(pat, "Description").text = p.description
        ET.SubElement(pat, "RiskScore").text = str(p.risk_score)

    txns = ET.SubElement(root, "Transactions")
    for t in transactions:
        tx = ET.SubElement(txns, "Transaction")
        ET.SubElement(tx, "Date").text = t.get("date", "")
        ET.SubElement(tx, "Amount").text = str(t.get("amount", ""))
        ET.SubElement(tx, "Currency").text = "GHS"
        ET.SubElement(tx, "Type").text = t.get("type", "")
        ET.SubElement(tx, "Method").text = t.get("method", "")
        ET.SubElement(tx, "Reference").text = t.get("reference", "")

    return ET.tostring(root, encoding="unicode", xml_declaration=False)


# ─── Engine ───────────────────────────────────────────────────────────────────

class AMLEngine:
    """High-level AML Engine — call from loan/savings transaction handlers."""

    def __init__(self, db: Session, institution_code: str, bog_licence: str) -> None:
        self.db = db
        self.institution_code = institution_code
        self.bog_licence = bog_licence

    def process_transaction(
        self,
        *,
        customer: Any,
        transaction: dict[str, Any],
        actor_id: str,
    ) -> dict[str, Any]:
        """Run AML checks on a transaction.

        Returns:
            dict with keys: ctr_required, str_required, patterns, alert_id
        """
        from api.models import AMLAlert
        from api.utils.audit_chain import write_audit

        amount = Decimal(str(transaction.get("amount", 0)))
        result: dict[str, Any] = {
            "ctr_required": False,
            "str_required": False,
            "patterns": [],
            "alert_id": None,
        }

        ctr_required = should_file_ctr(amount)
        recent_txns: list[dict] = []   # populated from DB in real implementation

        patterns = detect_suspicious_patterns(
            customer_id=customer.id,
            current_tx={**transaction, "kyc_region": getattr(customer, "region", "")},
            recent_transactions=recent_txns,
        )

        str_required = any(p.risk_score >= 70 for p in patterns)

        result["ctr_required"] = ctr_required
        result["str_required"] = str_required
        result["patterns"] = [{"code": p.code, "description": p.description} for p in patterns]

        if ctr_required or str_required:
            alert = AMLAlert(
                id=str(uuid.uuid4()),
                customer_id=customer.id,
                alert_type=AMLReportType.STR.value if str_required else AMLReportType.CTR.value,
                amount=float(amount),
                transaction_data=transaction,
                patterns=[{"code": p.code, "score": p.risk_score} for p in patterns],
                status=AMLAlertStatus.PENDING.value,
                triggered_at=datetime.now(timezone.utc),
            )
            self.db.add(alert)
            self.db.flush()
            result["alert_id"] = alert.id

            write_audit(
                self.db,
                table_name="aml_alerts",
                record_id=alert.id,
                action="AML_ALERT_CREATED",
                actor_id="SYSTEM",
                new_data={
                    "alert_type": alert.alert_type,
                    "amount": float(amount),
                    "ctr_required": ctr_required,
                    "str_required": str_required,
                },
                customer_id=customer.id,
            )

        return result
