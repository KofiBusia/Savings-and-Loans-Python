"""
GhIPSS Mobile Money Interoperability Interface (MMI) Adapter
Regulatory anchor: BoG Payment Systems Act 2019, GhIPSS Interoperability Framework

Supports:
  - MTN Mobile Money
  - Telecel Cash (formerly Vodafone)
  - AirtelTigo Money

Features:
  - Idempotency-key based deduplication (critical for unstable network)
  - Exponential backoff retry (3 attempts, max 60s)
  - Reconciliation endpoint
  - Full transaction audit trail
  - Mock mode for local/test environments
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, Literal

import httpx

log = logging.getLogger(__name__)

# ─── MNO Codes ────────────────────────────────────────────────────────────────

class MNO(str, Enum):
    MTN      = "MTN"
    TELECEL  = "TELECEL"
    AIRTELTIGO = "AIRTELTIGO"


# Phone prefix → MNO mapping
PHONE_TO_MNO: dict[str, MNO] = {
    "020": MNO.MTN, "024": MNO.MTN, "025": MNO.MTN, "054": MNO.MTN,
    "055": MNO.MTN, "059": MNO.MTN,
    "027": MNO.TELECEL, "057": MNO.TELECEL, "026": MNO.TELECEL,
    "028": MNO.AIRTELTIGO, "050": MNO.AIRTELTIGO,
    "053": MNO.AIRTELTIGO, "056": MNO.AIRTELTIGO,
}


def phone_to_mno(phone: str) -> MNO:
    """Determine MNO from Ghana phone number (0XX prefix)."""
    # Normalise to local format
    if phone.startswith("+233"):
        phone = "0" + phone[4:]
    prefix = phone[:3]
    if prefix not in PHONE_TO_MNO:
        raise ValueError(f"Phone prefix '{prefix}' is not a recognised Ghana MNO.")
    return PHONE_TO_MNO[prefix]


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class MMIRequest:
    amount: Decimal
    phone_number: str          # E.164 or local Ghana format
    reference: str             # Loan ID, repayment ID, etc.
    description: str
    direction: Literal["COLLECT", "DISBURSE"]
    idempotency_key: str = ""

    def __post_init__(self) -> None:
        if not self.idempotency_key:
            # Deterministic key: prevents double-disbursement on retry
            self.idempotency_key = hashlib.sha256(
                f"{self.reference}|{self.direction}|{self.amount}".encode()
            ).hexdigest()[:32]


@dataclass
class MMIResponse:
    success: bool
    transaction_id: str
    status: str                # SUCCESS | PENDING | FAILED | INSUFFICIENT_FUNDS
    mno: str
    amount: Decimal
    phone_number: str
    reference: str
    idempotency_key: str
    timestamp: str
    raw_response: dict[str, Any]
    error_code: str | None = None
    error_message: str | None = None


# ─── Retry Configuration ──────────────────────────────────────────────────────

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2   # seconds


# ─── GhIPSS MMI Client ────────────────────────────────────────────────────────

class GhIPSSMMIClient:
    """Unified GhIPSS MMI client for all Ghana MNOs.

    In mock mode (MOCK_GHIPSS=true in .env), returns simulated responses
    without hitting any real API. Use for development and CI.
    """

    # GhIPSS interoperability sandbox/production endpoints
    SANDBOX_URL = "https://sandbox.ghipss.net/api/v2/mmi"
    PRODUCTION_URL = "https://api.ghipss.net/api/v2/mmi"

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        institution_code: str,
        mock_mode: bool = False,
        production: bool = False,
    ) -> None:
        self.api_key = api_key
        self.api_secret = api_secret
        self.institution_code = institution_code
        self.mock_mode = mock_mode
        self.base_url = self.PRODUCTION_URL if production else self.SANDBOX_URL

    async def collect(self, req: MMIRequest) -> MMIResponse:
        """Collect payment from customer mobile wallet (loan repayment, savings)."""
        req.direction = "COLLECT"
        return await self._execute(req)

    async def disburse(self, req: MMIRequest) -> MMIResponse:
        """Disburse loan to customer mobile wallet."""
        req.direction = "DISBURSE"
        return await self._execute(req)

    async def check_status(self, idempotency_key: str) -> dict[str, Any]:
        """Check status of a previously submitted transaction."""
        if self.mock_mode:
            return {"status": "SUCCESS", "idempotency_key": idempotency_key, "mock": True}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/transactions/{idempotency_key}",
                headers=self._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def reconcile(self, *, date_str: str, page: int = 1) -> dict[str, Any]:
        """Fetch GhIPSS reconciliation report for a given date."""
        if self.mock_mode:
            return {"date": date_str, "records": [], "mock": True}
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(
                f"{self.base_url}/reconciliation",
                params={"date": date_str, "page": page, "institution": self.institution_code},
                headers=self._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _execute(self, req: MMIRequest) -> MMIResponse:
        if self.mock_mode:
            return self._mock_response(req)

        mno = phone_to_mno(req.phone_number)
        payload = self._build_payload(req, mno)

        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=45) as client:
                    resp = await client.post(
                        f"{self.base_url}/transactions",
                        json=payload,
                        headers=self._auth_headers(idempotency_key=req.idempotency_key),
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    log.info("ghipss_tx_success", ref=req.reference, attempt=attempt, mno=mno.value)
                    return self._parse_response(req, mno, data)

            except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError) as exc:
                last_error = exc
                if attempt < MAX_RETRIES:
                    wait = RETRY_BACKOFF_BASE ** attempt
                    log.warning(
                        "ghipss_tx_retry",
                        ref=req.reference,
                        attempt=attempt,
                        wait=wait,
                        error=str(exc),
                    )
                    await asyncio.sleep(wait)

        log.error("ghipss_tx_failed", ref=req.reference, error=str(last_error))
        return MMIResponse(
            success=False,
            transaction_id="",
            status="FAILED",
            mno=phone_to_mno(req.phone_number).value,
            amount=req.amount,
            phone_number=req.phone_number,
            reference=req.reference,
            idempotency_key=req.idempotency_key,
            timestamp=str(int(time.time())),
            raw_response={},
            error_code="NETWORK_FAILURE",
            error_message=str(last_error),
        )

    def _build_payload(self, req: MMIRequest, mno: MNO) -> dict[str, Any]:
        return {
            "institutionCode": self.institution_code,
            "mno": mno.value,
            "direction": req.direction,
            "amount": str(req.amount),
            "currency": "GHS",
            "phoneNumber": req.phone_number,
            "reference": req.reference,
            "description": req.description,
            "idempotencyKey": req.idempotency_key,
        }

    def _auth_headers(self, idempotency_key: str | None = None) -> dict[str, str]:
        sig = hashlib.sha256(
            f"{self.api_key}:{self.api_secret}:{int(time.time() // 300)}".encode()
        ).hexdigest()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "X-GhIPSS-Signature": sig,
            "X-Institution-Code": self.institution_code,
            "Content-Type": "application/json",
        }
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key
        return headers

    @staticmethod
    def _parse_response(req: MMIRequest, mno: MNO, data: dict[str, Any]) -> MMIResponse:
        return MMIResponse(
            success=data.get("status") == "SUCCESS",
            transaction_id=data.get("transactionId", ""),
            status=data.get("status", "UNKNOWN"),
            mno=mno.value,
            amount=req.amount,
            phone_number=req.phone_number,
            reference=req.reference,
            idempotency_key=req.idempotency_key,
            timestamp=data.get("timestamp", ""),
            raw_response=data,
            error_code=data.get("errorCode"),
            error_message=data.get("errorMessage"),
        )

    @staticmethod
    def _mock_response(req: MMIRequest) -> MMIResponse:
        """Deterministic mock — always succeeds unless amount >= 999999."""
        success = req.amount < Decimal("999999")
        return MMIResponse(
            success=success,
            transaction_id=f"MOCK-{uuid.uuid4().hex[:12].upper()}",
            status="SUCCESS" if success else "FAILED",
            mno=phone_to_mno(req.phone_number).value,
            amount=req.amount,
            phone_number=req.phone_number,
            reference=req.reference,
            idempotency_key=req.idempotency_key,
            timestamp=str(int(time.time())),
            raw_response={"mock": True},
            error_code=None if success else "INSUFFICIENT_FUNDS",
            error_message=None if success else "Mock: insufficient funds",
        )
