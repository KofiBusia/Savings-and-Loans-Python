"""
Ghana-Specific Field Validators
Regulatory anchor: AML Act 1044 (Ghana Card sole ID), Data Protection Act 843

All validators are pure functions — no DB access — so they can be used in
Pydantic models, FastAPI dependencies, and offline mobile pre-validation.
"""
from __future__ import annotations

import re
from typing import Literal

# ─── Ghana Card (NIA) ─────────────────────────────────────────────────────────

# Format: GHA-XXXXXXXXX-X or GHA-XXXXXXXXX-XX  (GHA + 9 digits + 1-2 digit check)
# Source: National Identification Authority Act 2006 (Act 707)
# NIA issues cards with either a 1- or 2-digit suffix (e.g. -5 or -01).
_GHANA_CARD_RE = re.compile(r"^GHA-(\d{9})-(\d{1,2})$")


def validate_ghana_card(card_number: str) -> str:
    """Validate and normalise a Ghana Card number.

    Validates format only — NIA has not published the check digit algorithm,
    so digit-level verification is intentionally omitted to avoid rejecting
    genuine cards.

    Raises:
        ValueError: If the format does not match GHA-XXXXXXXXX-X(X).

    Returns:
        Normalised card number (uppercase, stripped).
    """
    normalised = card_number.strip().upper()
    m = _GHANA_CARD_RE.match(normalised)
    if not m:
        raise ValueError(
            f"Invalid Ghana Card format '{card_number}'. "
            "Expected: GHA-XXXXXXXXX-X or GHA-XXXXXXXXX-XX (9 digits + 1–2 digit suffix)"
        )
    return normalised


# ─── Ghana Phone Numbers ──────────────────────────────────────────────────────

# Ghana MNO prefix mapping (as of 2024)
_MNO_MAP: dict[str, str] = {
    "020": "MTN", "024": "MTN", "025": "MTN", "054": "MTN", "055": "MTN", "059": "MTN",
    "027": "Telecel", "057": "Telecel", "026": "Telecel",
    "028": "AirtelTigo", "050": "AirtelTigo", "053": "AirtelTigo", "056": "AirtelTigo",
    "030": "Landline-Accra", "031": "Landline-Kumasi",
}


def validate_ghana_phone(phone: str) -> tuple[str, str]:
    """Validate and normalise a Ghana phone number.

    Accepts: 0244123456, +233244123456, 233244123456
    Returns: (e164: '+233XXXXXXXXX', mno: 'MTN'|'Telecel'|'AirtelTigo'|...)
    Raises: ValueError if invalid.
    """
    raw = re.sub(r"[\s\-\(\)]", "", phone)
    if raw.startswith("+233"):
        raw = "0" + raw[4:]
    elif raw.startswith("233") and len(raw) == 12:
        raw = "0" + raw[3:]

    if not re.match(r"^0\d{9}$", raw):
        raise ValueError(
            f"Invalid Ghana phone number '{phone}'. "
            "Expected 10-digit Ghana number (e.g. 0244123456)."
        )
    prefix = raw[:3]
    mno = _MNO_MAP.get(prefix, "Unknown")
    e164 = "+233" + raw[1:]
    return e164, mno


def is_momo_capable(phone: str) -> bool:
    """Return True if the MNO supports Mobile Money (GhIPSS MMI)."""
    try:
        _, mno = validate_ghana_phone(phone)
        return mno in ("MTN", "Telecel", "AirtelTigo")
    except ValueError:
        return False


# ─── GhanaPost GPS ────────────────────────────────────────────────────────────

# Format: XX-XXXX-XXXX (Region code + 4 alphanums + 4 alphanums)
_GHANAPOST_RE = re.compile(r"^[A-Z]{2}-\d{4}-\d{4}$")


def validate_ghana_post_gps(gps: str) -> str:
    """Validate a GhanaPost GPS address.

    Raises: ValueError if format is invalid.
    Returns: Normalised GPS address.
    """
    normalised = gps.strip().upper().replace(" ", "-")
    if not _GHANAPOST_RE.match(normalised):
        raise ValueError(
            f"Invalid GhanaPost GPS '{gps}'. Expected format: XX-XXXX-XXXX"
        )
    return normalised


# ─── Ghana Regions ────────────────────────────────────────────────────────────

GHANA_REGIONS: frozenset[str] = frozenset({
    "Greater Accra", "Ashanti", "Western", "Eastern", "Central",
    "Volta", "Northern", "Upper East", "Upper West", "Brong-Ahafo",
    "Oti", "Bono East", "Ahafo", "Western North",
    "Savannah", "North East",
})


def validate_ghana_region(region: str) -> str:
    """Validate that a region name is one of the 16 official Ghana regions."""
    for r in GHANA_REGIONS:
        if r.lower() == region.strip().lower():
            return r
    raise ValueError(
        f"'{region}' is not a recognised Ghana region. "
        f"Valid regions: {sorted(GHANA_REGIONS)}"
    )


# ─── GRA Tax Identification Number ───────────────────────────────────────────

# GRA TIN format: C0000000000 (individual) or P0000000000 (company)
_TIN_RE = re.compile(r"^[CP]\d{10}$")


def validate_tin(tin: str) -> str:
    """Validate a Ghana Revenue Authority TIN.

    Raises: ValueError if invalid.
    """
    normalised = tin.strip().upper()
    if not _TIN_RE.match(normalised):
        raise ValueError(
            f"Invalid GRA TIN '{tin}'. Expected format: C0000000000 (individual) "
            "or P0000000000 (company)"
        )
    return normalised


# ─── Bank of Ghana Licence Number ────────────────────────────────────────────

def validate_bog_licence(licence: str) -> str:
    """Validate BoG licence number format (ARN/MFI/SDI prefixes)."""
    normalised = licence.strip().upper()
    if not re.match(r"^(ARN|MFI|SDI|PSP|EMI)-\d{3,6}/\d{4}$", normalised):
        raise ValueError(
            f"Invalid BoG licence '{licence}'. "
            "Expected format: MFI-001234/2023"
        )
    return normalised


# ─── IBAN / Account Number ────────────────────────────────────────────────────

def validate_account_number(account: str) -> str:
    """Validate internal account number format (900XXXXXXX)."""
    normalised = account.strip()
    if not re.match(r"^900\d{7}$", normalised):
        raise ValueError(
            f"Invalid account number '{account}'. Expected 10-digit number starting with 900."
        )
    return normalised


# ─── Loan Purpose Classification ─────────────────────────────────────────────

LoanPurpose = Literal[
    "WORKING_CAPITAL", "ASSET_PURCHASE", "EDUCATION", "HEALTH",
    "AGRICULTURE", "TRADE", "CONSTRUCTION", "PERSONAL", "OTHER",
]

VALID_LOAN_PURPOSES: frozenset[str] = frozenset({
    "WORKING_CAPITAL", "ASSET_PURCHASE", "EDUCATION", "HEALTH",
    "AGRICULTURE", "TRADE", "CONSTRUCTION", "PERSONAL", "OTHER",
})


def validate_loan_purpose(purpose: str) -> str:
    p = purpose.strip().upper()
    if p not in VALID_LOAN_PURPOSES:
        raise ValueError(f"Invalid loan purpose '{purpose}'. Valid: {sorted(VALID_LOAN_PURPOSES)}")
    return p
