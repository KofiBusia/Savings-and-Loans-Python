"""
Ghana Credit Bureau Integration Adapters
Regulatory anchor: Credit Reporting Regulations 2020 (L.I. 2394), Regulation 8
"Every lender shall submit credit data to all licensed credit bureaus in Ghana
in the format prescribed by the Bank of Ghana."

Supported bureaus:
  - XDS Data Ghana
  - D&B Ghana (Dun & Bradstreet)
  - MyCredit Score Ghana

Submission schedule: Daily (not later than 9:00 AM for previous day's data)
Format: BoG-prescribed fixed-width / XML hybrid format
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any

import httpx

log = logging.getLogger(__name__)


# ─── Types ────────────────────────────────────────────────────────────────────

class BureauName(str, Enum):
    XDS        = "XDS"
    DB_GHANA   = "DB_GHANA"
    MY_CREDIT  = "MY_CREDIT_SCORE"


class LoanStatus(str, Enum):
    CURRENT        = "CUR"    # BoG code
    PAST_DUE_30    = "PD1"
    PAST_DUE_60    = "PD2"
    PAST_DUE_90    = "PD3"
    PAST_DUE_180   = "PD6"
    WRITTEN_OFF    = "WO"
    RESTRUCTURED   = "RST"
    SETTLED        = "SET"
    CLOSED         = "CLO"


# ─── Credit Record ────────────────────────────────────────────────────────────

@dataclass
class CreditRecord:
    """One row in the daily BoG credit submission file."""
    institution_code: str
    account_number: str
    ghana_card_number: str
    customer_name: str
    date_of_birth: date
    phone_number: str
    loan_type: str                  # e.g. MICROCREDIT, PERSONAL, SME
    currency: str = "GHS"
    original_amount: Decimal = Decimal("0")
    outstanding_balance: Decimal = Decimal("0")
    monthly_instalment: Decimal = Decimal("0")
    disbursement_date: date = field(default_factory=date.today)
    maturity_date: date = field(default_factory=date.today)
    days_past_due: int = 0
    account_status: LoanStatus = LoanStatus.CURRENT
    number_of_arrears: int = 0
    credit_limit: Decimal = Decimal("0")
    collateral_type: str = "NONE"
    collateral_value: Decimal = Decimal("0")

    def to_bog_dict(self) -> dict[str, str]:
        """Serialise to BoG-prescribed field names."""
        return {
            "INST_CODE": self.institution_code,
            "ACCT_NUM": self.account_number,
            "GHANA_CARD": self.ghana_card_number,
            "CUST_NAME": self.customer_name[:100],
            "DATE_OF_BIRTH": self.date_of_birth.strftime("%Y%m%d"),
            "PHONE": self.phone_number,
            "LOAN_TYPE": self.loan_type,
            "CURRENCY": self.currency,
            "ORIGINAL_AMT": f"{self.original_amount:.2f}",
            "OS_BALANCE": f"{self.outstanding_balance:.2f}",
            "MONTHLY_INST": f"{self.monthly_instalment:.2f}",
            "DISB_DATE": self.disbursement_date.strftime("%Y%m%d"),
            "MAT_DATE": self.maturity_date.strftime("%Y%m%d"),
            "DPD": str(self.days_past_due).zfill(3),
            "ACCT_STATUS": self.account_status.value,
            "NO_ARREARS": str(self.number_of_arrears).zfill(2),
            "COLL_TYPE": self.collateral_type,
            "COLL_VALUE": f"{self.collateral_value:.2f}",
        }

    def validate(self) -> list[str]:
        """Return list of validation errors. Empty list = valid."""
        errors: list[str] = []
        if not self.ghana_card_number.startswith("GHA-"):
            errors.append(f"Invalid Ghana Card: {self.ghana_card_number}")
        if self.outstanding_balance < 0:
            errors.append("Outstanding balance cannot be negative")
        if self.days_past_due < 0:
            errors.append("Days past due cannot be negative")
        if self.original_amount <= 0:
            errors.append("Original loan amount must be positive")
        return errors


# ─── Submission Result ────────────────────────────────────────────────────────

@dataclass
class BureauSubmissionResult:
    bureau: BureauName
    submission_date: date
    record_count: int
    checksum: str
    success: bool
    acknowledgment_reference: str | None = None
    error_message: str | None = None


# ─── Bureau Clients ───────────────────────────────────────────────────────────

class _BaseBureauClient:
    """Base class for all credit bureau clients."""

    def __init__(
        self,
        api_key: str,
        api_url: str,
        institution_code: str,
        mock_mode: bool = False,
    ) -> None:
        self.api_key = api_key
        self.api_url = api_url
        self.institution_code = institution_code
        self.mock_mode = mock_mode

    def _compute_checksum(self, records: list[CreditRecord]) -> str:
        payload = json.dumps([r.to_bog_dict() for r in records], sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()

    def _validate_all(self, records: list[CreditRecord]) -> None:
        for i, rec in enumerate(records):
            errors = rec.validate()
            if errors:
                raise ValueError(
                    f"Record {i} (account {rec.account_number}) failed validation: {errors}"
                )

    async def submit(self, records: list[CreditRecord]) -> BureauSubmissionResult:
        raise NotImplementedError


class XDSClient(_BaseBureauClient):
    """XDS Data Ghana credit bureau client."""

    async def submit(self, records: list[CreditRecord]) -> BureauSubmissionResult:
        self._validate_all(records)
        checksum = self._compute_checksum(records)

        if self.mock_mode:
            log.info("xds_mock_submission", count=len(records))
            return BureauSubmissionResult(
                bureau=BureauName.XDS,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=True,
                acknowledgment_reference=f"XDS-MOCK-{uuid.uuid4().hex[:8].upper()}",
            )

        payload = {
            "institutionCode": self.institution_code,
            "submissionDate": date.today().isoformat(),
            "recordCount": len(records),
            "checksum": checksum,
            "records": [r.to_bog_dict() for r in records],
        }
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.api_url}/submissions/daily",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "X-Institution-Code": self.institution_code},
            )
            resp.raise_for_status()
            data = resp.json()
            return BureauSubmissionResult(
                bureau=BureauName.XDS,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=data.get("status") == "ACCEPTED",
                acknowledgment_reference=data.get("acknowledgmentRef"),
            )


class DBGhanaClient(_BaseBureauClient):
    """D&B Ghana credit bureau client."""

    async def submit(self, records: list[CreditRecord]) -> BureauSubmissionResult:
        self._validate_all(records)
        checksum = self._compute_checksum(records)

        if self.mock_mode:
            return BureauSubmissionResult(
                bureau=BureauName.DB_GHANA,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=True,
                acknowledgment_reference=f"DB-MOCK-{uuid.uuid4().hex[:8].upper()}",
            )
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.api_url}/data/upload",
                json={"data": [r.to_bog_dict() for r in records],
                      "meta": {"institution": self.institution_code, "checksum": checksum}},
                headers={"X-API-Key": self.api_key},
            )
            resp.raise_for_status()
            data = resp.json()
            return BureauSubmissionResult(
                bureau=BureauName.DB_GHANA,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=True,
                acknowledgment_reference=data.get("batchId"),
            )


class MyCreditScoreClient(_BaseBureauClient):
    """MyCredit Score Ghana bureau client."""

    async def submit(self, records: list[CreditRecord]) -> BureauSubmissionResult:
        self._validate_all(records)
        checksum = self._compute_checksum(records)

        if self.mock_mode:
            return BureauSubmissionResult(
                bureau=BureauName.MY_CREDIT,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=True,
                acknowledgment_reference=f"MC-MOCK-{uuid.uuid4().hex[:8].upper()}",
            )
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.api_url}/v1/batch-upload",
                json={"records": [r.to_bog_dict() for r in records],
                      "checksum": checksum,
                      "institution": self.institution_code},
                headers={"Authorization": f"Key {self.api_key}"},
            )
            resp.raise_for_status()
            data = resp.json()
            return BureauSubmissionResult(
                bureau=BureauName.MY_CREDIT,
                submission_date=date.today(),
                record_count=len(records),
                checksum=checksum,
                success=data.get("accepted", False),
                acknowledgment_reference=data.get("reference"),
            )


# ─── Unified Submission Manager ───────────────────────────────────────────────

class CreditBureauManager:
    """Submit daily credit data to all three BoG-mandated bureaus."""

    def __init__(
        self,
        xds: XDSClient,
        db_ghana: DBGhanaClient,
        my_credit: MyCreditScoreClient,
    ) -> None:
        self._clients = {
            BureauName.XDS: xds,
            BureauName.DB_GHANA: db_ghana,
            BureauName.MY_CREDIT: my_credit,
        }

    async def submit_daily(self, records: list[CreditRecord]) -> list[BureauSubmissionResult]:
        """Submit to all three bureaus. Returns list of results (one per bureau)."""
        import asyncio
        tasks = [client.submit(records) for client in self._clients.values()]
        return await asyncio.gather(*tasks, return_exceptions=False)
