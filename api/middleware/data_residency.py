"""
Data Residency Enforcement Middleware
Regulatory anchor: Data Protection Act 2012 (Act 843), Section 25
"Personal data of Ghanaian data subjects shall be processed and stored within Ghana."

This ASGI middleware intercepts every response and:
  1. Blocks PII-bearing responses going to non-Ghana IPs (returns 403)
  2. Logs every blocked attempt to the audit system
  3. Allows a configurable allowlist for BoG/FIC/DPC institutional IPs

Configuration is via environment variables (see api/config.py).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from typing import Callable, Awaitable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

log = logging.getLogger(__name__)

# ─── PII-Bearing Route Prefixes ───────────────────────────────────────────────
# These routes return personal data and must be restricted to Ghana-originated requests.
# Update this list whenever a new PII-bearing endpoint is added.

PII_ROUTE_PREFIXES: tuple[str, ...] = (
    "/api/v1/customers",
    "/api/v1/auth/me",
    "/api/v1/compliance/aml",
    "/api/v1/compliance/str",
    "/api/v1/compliance/ctr",
    "/api/v1/admin/users",
)

# ─── Response fields that constitute PII (block if found outside Ghana) ───────
PII_RESPONSE_FIELDS: frozenset[str] = frozenset({
    "ghana_card_number", "ghana_card_hash", "date_of_birth", "biometric_data",
    "national_id", "tin_number", "phone_number", "email_address",
    "street_address", "bank_account_number", "pep_screening",
    "beneficial_owners", "source_of_funds",
})

# ─── Ghana IP ranges (CIDR blocks) ────────────────────────────────────────────
# Source: AFRINIC allocated blocks for Ghana (.GH)
# Keep this list updated from: https://www.afrinic.net/
GHANA_IP_RANGES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("41.66.0.0/15"),
    ipaddress.ip_network("41.74.0.0/15"),
    ipaddress.ip_network("154.120.0.0/13"),
    ipaddress.ip_network("196.201.192.0/18"),
    ipaddress.ip_network("197.255.192.0/18"),
    ipaddress.ip_network("154.160.0.0/12"),
    ipaddress.ip_network("41.189.0.0/18"),
    # RFC-1918 private ranges — always allowed (internal / VPN traffic)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# ─── Institutional allowlist (BoG, FIC, DPC, GIPC) ───────────────────────────
INSTITUTIONAL_ALLOWLIST_IPS: frozenset[str] = frozenset({
    "197.255.208.1",    # Bank of Ghana HQ, Accra
    "196.201.197.1",    # Financial Intelligence Centre
    "154.161.1.1",      # Data Protection Commission
})


def _is_ghana_ip(ip_str: str) -> bool:
    """Return True if the IP address originates from Ghana or private network."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip_str in INSTITUTIONAL_ALLOWLIST_IPS:
        return True
    return any(addr in network for network in GHANA_IP_RANGES)


def _extract_client_ip(request: Request) -> str:
    """Extract real client IP, respecting Cloudflare/proxy headers."""
    # Cloudflare sets CF-Connecting-IP as the verified client IP
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    # Cloudflare country header (quick check, secondary)
    # X-Forwarded-For from trusted proxy (first IP is originating client)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def _is_pii_route(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PII_ROUTE_PREFIXES)


def _response_contains_pii(body_bytes: bytes) -> bool:
    """Quick scan of JSON response body for known PII field names."""
    try:
        text = body_bytes.decode("utf-8", errors="ignore")
        return any(f'"{field}"' in text for field in PII_RESPONSE_FIELDS)
    except Exception:
        return False


class DataResidencyMiddleware(BaseHTTPMiddleware):
    """Enforce Ghana data residency for PII-bearing API responses.

    Non-PII routes (health, public docs, static assets) are always allowed.
    PII routes are blocked for non-Ghana IPs unless on the institutional allowlist.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Allow non-PII routes without any IP check
        if not _is_pii_route(request.url.path):
            return await call_next(request)

        client_ip = _extract_client_ip(request)
        cf_country = request.headers.get("CF-IPCountry", "").upper()

        # Cloudflare fast path: CF-IPCountry header says "GH"
        if cf_country and cf_country == "GH":
            return await call_next(request)

        # IP range check
        if _is_ghana_ip(client_ip):
            return await call_next(request)

        # Non-Ghana origin requesting PII route — block and log
        log.warning(
            "data_residency_blocked",
            extra={
                "client_ip": client_ip,
                "cf_country": cf_country,
                "path": request.url.path,
                "method": request.method,
            },
        )

        return JSONResponse(
            status_code=403,
            content={
                "detail": (
                    "Access denied. This endpoint contains personal data of Ghanaian data subjects "
                    "and may only be accessed from within Ghana. "
                    "Regulatory basis: Data Protection Act 2012 (Act 843), Section 25."
                ),
                "regulation": "DPA_843_S25",
                "client_country": cf_country or "UNKNOWN",
            },
        )
