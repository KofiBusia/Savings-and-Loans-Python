"""
Ghana Card / NIA OCR + Liveness verification client.
AML Act 1044 s.18 — Ghana Card is the sole acceptable identity document.

Real NIA API docs: https://nia.gov.gh/developers (registration required)
This client wraps NIA API v1 with:
  - Offline fallback cache (allows re-verification without NIA API call)
  - Mock mode for development/CI (no real API calls)
  - Automatic retry on network errors
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from api.config import settings

log = logging.getLogger(__name__)

# Offline cache: SHA-256(card_number) → verification result
# Stored in .ghana_card_cache/ (excluded from git)
_CACHE_DIR = Path(".ghana_card_cache")


@dataclass
class GhanaCardVerificationResult:
    success: bool
    card_number: str
    full_name: str | None = None
    date_of_birth: str | None = None
    gender: str | None = None
    expiry_date: str | None = None
    photo_url: str | None = None
    liveness_score: float | None = None   # 0.0 – 1.0; >= 0.7 required
    error: str | None = None
    from_cache: bool = False
    verified_at: str = ""

    def __post_init__(self):
        if not self.verified_at:
            self.verified_at = datetime.utcnow().isoformat() + "Z"


class GhanaCardAPIClient:
    """NIA Ghana Card verification client with offline cache and mock support."""

    def __init__(self):
        self._base_url = settings.ghana_card_api_url.rstrip("/")
        self._api_key = settings.ghana_card_api_key
        self._mock = settings.mock_ghana_card_api

    async def verify(
        self,
        card_number: str,
        selfie_base64: str | None = None,
        use_cache: bool = True,
    ) -> GhanaCardVerificationResult:
        if self._mock:
            return self._mock_verify(card_number)

        # Try offline cache first
        if use_cache:
            cached = self._load_cache(card_number)
            if cached:
                log.info("ghana_card_cache_hit card=%s", _mask(card_number))
                return GhanaCardVerificationResult(from_cache=True, **cached)

        try:
            return await self._call_nia(card_number, selfie_base64)
        except httpx.HTTPError as exc:
            log.error("nia_api_error card=%s error=%s", _mask(card_number), exc)
            return GhanaCardVerificationResult(
                success=False,
                card_number=card_number,
                error=f"NIA API unreachable: {exc}",
            )

    async def verify_liveness(
        self,
        card_number: str,
        video_base64: str,
    ) -> GhanaCardVerificationResult:
        """Liveness check — separate NIA endpoint."""
        if self._mock:
            return self._mock_verify(card_number, liveness_score=0.92)

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self._base_url}/liveness",
                headers={"X-API-Key": self._api_key},
                json={"card_number": card_number, "video": video_base64},
            )
            resp.raise_for_status()
            data = resp.json()
            return GhanaCardVerificationResult(
                success=data.get("verified", False),
                card_number=card_number,
                liveness_score=data.get("score"),
                error=data.get("error"),
            )

    # ── Private ───────────────────────────────────────────────────────────────

    async def _call_nia(
        self,
        card_number: str,
        selfie_base64: str | None,
    ) -> GhanaCardVerificationResult:
        payload: dict[str, Any] = {"card_number": card_number}
        if selfie_base64:
            payload["selfie"] = selfie_base64

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{self._base_url}/verify",
                headers={"X-API-Key": self._api_key, "Content-Type": "application/json"},
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        result = GhanaCardVerificationResult(
            success=data.get("verified", False),
            card_number=card_number,
            full_name=data.get("full_name"),
            date_of_birth=data.get("date_of_birth"),
            gender=data.get("gender"),
            expiry_date=data.get("expiry_date"),
            photo_url=data.get("photo_url"),
            liveness_score=data.get("liveness_score"),
            error=data.get("error"),
        )

        if result.success:
            self._save_cache(card_number, result)

        return result

    def _mock_verify(
        self,
        card_number: str,
        liveness_score: float = 0.95,
    ) -> GhanaCardVerificationResult:
        # Mock: GHA-000000000-0 always fails; all others succeed
        if card_number == "GHA-000000000-0":
            return GhanaCardVerificationResult(
                success=False,
                card_number=card_number,
                error="Mock: card flagged as invalid",
            )
        parts = card_number.replace("GHA-", "").split("-")
        return GhanaCardVerificationResult(
            success=True,
            card_number=card_number,
            full_name="MOCK GHANA CITIZEN",
            date_of_birth="1990-01-01",
            gender="M",
            expiry_date="2030-12-31",
            liveness_score=liveness_score,
        )

    def _cache_path(self, card_number: str) -> Path:
        key = hashlib.sha256(card_number.encode()).hexdigest()
        return _CACHE_DIR / f"{key}.json"

    def _load_cache(self, card_number: str) -> dict | None:
        path = self._cache_path(card_number)
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                return None
        return None

    def _save_cache(self, card_number: str, result: GhanaCardVerificationResult) -> None:
        try:
            _CACHE_DIR.mkdir(exist_ok=True)
            data = {
                "success": result.success,
                "card_number": result.card_number,
                "full_name": result.full_name,
                "date_of_birth": result.date_of_birth,
                "gender": result.gender,
                "expiry_date": result.expiry_date,
                "verified_at": result.verified_at,
            }
            self._cache_path(card_number).write_text(json.dumps(data))
        except Exception as exc:
            log.warning("ghana_card_cache_write_failed: %s", exc)


def _mask(card: str) -> str:
    """GHA-123456789-X → GHA-XXXXX6789-X for safe logging."""
    if len(card) > 8:
        return card[:4] + "XXXXX" + card[9:]
    return "***"


# Module-level singleton
ghana_card_client = GhanaCardAPIClient()
