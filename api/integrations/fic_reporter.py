"""
FIC (Financial Intelligence Centre) submission client.
Handles submission of CTRs, STRs, and goAML reports.

FIC goAML portal: https://goaml.fic.gov.gh
Regulatory basis: AML Act 2020 (Act 1044) ss.22, 36
Deadline tracking: CTR within 5 days; STR within 3 days of suspicion
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import httpx

from api.config import settings

log = logging.getLogger(__name__)

# Filing deadlines (AML Act 1044)
CTR_FILING_DAYS = 5    # CTR must be filed within 5 business days
STR_FILING_DAYS = 3    # STR must be filed within 3 business days of suspicion


@dataclass
class FICSubmission:
    report_type: str   # CTR | STR
    reference: str
    xml_payload: str
    customer_id: str
    transaction_id: str | None = None
    amount_ghs: str | None = None
    narrative: str | None = None
    deadline: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        days = CTR_FILING_DAYS if self.report_type == "CTR" else STR_FILING_DAYS
        self.deadline = datetime.utcnow() + timedelta(days=days)


@dataclass
class FICResponse:
    success: bool
    fic_reference: str | None = None
    status: str = ""
    submitted_at: str = ""
    error: str | None = None
    raw: dict | None = None

    def __post_init__(self):
        if not self.submitted_at:
            self.submitted_at = datetime.utcnow().isoformat() + "Z"


class FICReporterClient:
    """
    Client for FIC goAML API.
    In mock mode (development/CI), submissions are logged locally but not sent.
    """

    def __init__(self):
        self._base_url = settings.fic_submission_url.rstrip("/")
        self._api_key = settings.fic_api_key
        self._mock = settings.node_env in ("development", "test")

    async def submit_ctr(self, submission: FICSubmission) -> FICResponse:
        """
        Submit Currency Transaction Report.
        Required for transactions >= GHS 10,000 (AML Act 1044 s.22).
        """
        return await self._submit(submission, endpoint="/ctr")

    async def submit_str(self, submission: FICSubmission) -> FICResponse:
        """
        Submit Suspicious Transaction Report.
        Required for any transaction where suspicion arises (AML Act 1044 s.36).
        """
        return await self._submit(submission, endpoint="/str")

    async def check_status(self, fic_reference: str) -> dict[str, Any]:
        """Poll submission status from FIC goAML portal."""
        if self._mock:
            return {"status": "ACKNOWLEDGED", "reference": fic_reference}

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self._base_url}/status/{fic_reference}",
                headers=self._auth_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    def get_deadline(self, report_type: str) -> datetime:
        days = CTR_FILING_DAYS if report_type == "CTR" else STR_FILING_DAYS
        return datetime.utcnow() + timedelta(days=days)

    # ── Private ───────────────────────────────────────────────────────────────

    async def _submit(self, submission: FICSubmission, endpoint: str) -> FICResponse:
        if self._mock:
            return self._mock_submit(submission)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self._base_url}{endpoint}",
                    headers={**self._auth_headers(), "Content-Type": "application/xml"},
                    content=submission.xml_payload.encode("utf-8"),
                )
                resp.raise_for_status()
                data = resp.json()

            fic_ref = data.get("reference") or f"FIC-{submission.report_type}-{submission.reference}"
            log.info("fic_submitted type=%s ref=%s fic_ref=%s",
                     submission.report_type, submission.reference, fic_ref)

            return FICResponse(
                success=True,
                fic_reference=fic_ref,
                status=data.get("status", "SUBMITTED"),
                raw=data,
            )

        except httpx.HTTPError as exc:
            log.error("fic_submission_failed type=%s ref=%s error=%s",
                      submission.report_type, submission.reference, exc)
            return FICResponse(
                success=False,
                status="FAILED",
                error=str(exc),
            )

    def _mock_submit(self, submission: FICSubmission) -> FICResponse:
        fic_ref = f"MOCK-{submission.report_type}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        log.info("fic_mock_submit type=%s ref=%s → %s",
                 submission.report_type, submission.reference, fic_ref)
        return FICResponse(
            success=True,
            fic_reference=fic_ref,
            status="MOCK_SUBMITTED",
        )

    def _auth_headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self._api_key,
            "X-Institution-Code": settings.ghipss_institution_code,
            "X-Reporting-Officer": settings.fic_reporting_officer,
        }


# Module-level singleton
fic_client = FICReporterClient()
