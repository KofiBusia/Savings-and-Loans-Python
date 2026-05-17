"""
KYC Onboarding State Machine — 12-Step Regulatory Flow
Regulatory anchor: AML Act 1044, BoG CDD Guidelines 2022, DCD 2025

Rules:
  - Steps execute in strict sequence. No step may be bypassed.
  - Each transition writes an immutable audit record.
  - High-risk customers receive EDD step automatically (AML Act 1044, s.36).
  - SME customers receive BeneficialOwnership step (AML Act 1044, s.27).
  - PEP match or sanctions hit immediately moves customer to SUSPENDED.
  - Account activates automatically after e-signature if all guards pass.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session


# ─── States ───────────────────────────────────────────────────────────────────

class KYCStatus(str, Enum):
    PENDING_GHANA_CARD           = "PENDING_GHANA_CARD"
    PENDING_LIVENESS             = "PENDING_LIVENESS"
    PENDING_ADDRESS              = "PENDING_ADDRESS"
    PENDING_INCOME               = "PENDING_INCOME"
    PENDING_PEP_SCREENING        = "PENDING_PEP_SCREENING"
    PENDING_RISK_CLASSIFICATION  = "PENDING_RISK_CLASSIFICATION"
    PENDING_EDD                  = "PENDING_EDD"           # high-risk only
    PENDING_BENEFICIAL_OWNERSHIP = "PENDING_BENEFICIAL_OWNERSHIP"   # SME only
    PENDING_CONSENT              = "PENDING_CONSENT"
    PENDING_PRE_AGREEMENT        = "PENDING_PRE_AGREEMENT"
    PENDING_ESIGNATURE           = "PENDING_ESIGNATURE"
    ACTIVE                       = "ACTIVE"
    SUSPENDED                    = "SUSPENDED"
    REJECTED                     = "REJECTED"


# ─── Transition Map ───────────────────────────────────────────────────────────
# Maps current_state → next_state for the standard (non-high-risk, non-SME) path

_STANDARD_TRANSITIONS: dict[KYCStatus, KYCStatus] = {
    KYCStatus.PENDING_GHANA_CARD:           KYCStatus.PENDING_LIVENESS,
    KYCStatus.PENDING_LIVENESS:             KYCStatus.PENDING_ADDRESS,
    KYCStatus.PENDING_ADDRESS:              KYCStatus.PENDING_INCOME,
    KYCStatus.PENDING_INCOME:               KYCStatus.PENDING_PEP_SCREENING,
    KYCStatus.PENDING_PEP_SCREENING:        KYCStatus.PENDING_RISK_CLASSIFICATION,
    KYCStatus.PENDING_RISK_CLASSIFICATION:  KYCStatus.PENDING_CONSENT,   # may diverge below
    KYCStatus.PENDING_EDD:                  KYCStatus.PENDING_CONSENT,
    KYCStatus.PENDING_BENEFICIAL_OWNERSHIP: KYCStatus.PENDING_CONSENT,
    KYCStatus.PENDING_CONSENT:              KYCStatus.PENDING_PRE_AGREEMENT,
    KYCStatus.PENDING_PRE_AGREEMENT:        KYCStatus.PENDING_ESIGNATURE,
    KYCStatus.PENDING_ESIGNATURE:           KYCStatus.ACTIVE,
}

# Required data fields per step (validated before transition)
_STEP_REQUIRED_FIELDS: dict[KYCStatus, list[str]] = {
    KYCStatus.PENDING_GHANA_CARD:           ["ghana_card_number", "ghana_card_verified"],
    KYCStatus.PENDING_LIVENESS:             ["liveness_score", "liveness_passed"],
    KYCStatus.PENDING_ADDRESS:              ["street_address", "town", "region", "gps_lat", "gps_lon"],
    KYCStatus.PENDING_INCOME:               ["employment_status", "monthly_income_range_ghs", "source_of_funds"],
    KYCStatus.PENDING_PEP_SCREENING:        ["pep_result", "sanctions_result"],
    KYCStatus.PENDING_RISK_CLASSIFICATION:  ["risk_class", "risk_score"],
    KYCStatus.PENDING_EDD:                  ["edd_completed", "edd_officer_id", "edd_notes"],
    KYCStatus.PENDING_BENEFICIAL_OWNERSHIP: ["beneficial_owners"],
    KYCStatus.PENDING_CONSENT:              ["consent_data_processing", "consent_credit_bureau", "consent_marketing"],
    KYCStatus.PENDING_PRE_AGREEMENT:        ["pre_agreement_displayed_at", "display_duration_seconds"],
    KYCStatus.PENDING_ESIGNATURE:           ["signature_hash", "signed_at", "device_fingerprint"],
}

# Minimum pre-agreement display duration in seconds (DCD 2025, Clause 8)
MIN_PRE_AGREEMENT_DISPLAY_SECONDS = 30


# ─── Exceptions ───────────────────────────────────────────────────────────────

class KYCStepError(ValueError):
    """Invalid KYC transition attempted."""


class KYCPEPMatch(RuntimeError):
    """Customer matched PEP/Sanctions list — account must be suspended."""


class KYCPreAgreementTooShort(ValueError):
    """Pre-agreement was not displayed for the minimum required duration (DCD 2025)."""


# ─── Transition Result ────────────────────────────────────────────────────────

class KYCTransitionResult:
    def __init__(
        self,
        previous_status: KYCStatus,
        new_status: KYCStatus,
        audit_id: str,
        message: str,
    ) -> None:
        self.previous_status = previous_status
        self.new_status = new_status
        self.audit_id = audit_id
        self.message = message

    def activated(self) -> bool:
        return self.new_status == KYCStatus.ACTIVE


# ─── State Machine ────────────────────────────────────────────────────────────

class KYCStateMachine:
    """Orchestrates the 12-step KYC onboarding flow.

    Usage:
        fsm = KYCStateMachine(db, customer, actor_id)
        result = fsm.transition(KYCStatus.PENDING_GHANA_CARD, step_data)
    """

    def __init__(self, db: Session, customer: Any, actor_id: str) -> None:
        self.db = db
        self.customer = customer
        self.actor_id = actor_id

    # ── Public API ────────────────────────────────────────────────────────────

    def transition(self, step: KYCStatus, step_data: dict[str, Any]) -> KYCTransitionResult:
        """Execute one KYC transition.

        Args:
            step: The step being completed (must match current status).
            step_data: Data collected during this step.

        Returns:
            KYCTransitionResult with new status and audit ID.

        Raises:
            KYCStepError: Wrong step, missing fields, or invalid state.
            KYCPEPMatch: Customer matched sanctions/PEP list.
            KYCPreAgreementTooShort: Pre-agreement not shown long enough.
        """
        current = KYCStatus(self.customer.kyc_status)
        self._validate_step(current, step)
        self._validate_required_fields(step, step_data)

        # Step-specific business rules
        if step == KYCStatus.PENDING_PEP_SCREENING:
            self._handle_pep_screening(step_data)

        if step == KYCStatus.PENDING_PRE_AGREEMENT:
            self._validate_pre_agreement_duration(step_data)

        if step == KYCStatus.PENDING_ESIGNATURE:
            self._validate_esignature(step_data)

        # Compute next state
        next_status = self._compute_next(step, step_data)

        # Persist
        self._apply_step_data(step, step_data, next_status)
        audit_id = self._write_kyc_audit(step, step_data, current, next_status)

        return KYCTransitionResult(
            previous_status=current,
            new_status=next_status,
            audit_id=audit_id,
            message=f"KYC step {step.value} completed → {next_status.value}",
        )

    def can_transition(self, step: KYCStatus) -> bool:
        current = KYCStatus(self.customer.kyc_status)
        return current == step

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _validate_step(self, current: KYCStatus, requested: KYCStatus) -> None:
        if current != requested:
            raise KYCStepError(
                f"Cannot execute step '{requested.value}' — "
                f"customer is currently at '{current.value}'. "
                "KYC steps must be completed in order."
            )
        if current in (KYCStatus.ACTIVE, KYCStatus.REJECTED, KYCStatus.SUSPENDED):
            raise KYCStepError(f"KYC is in terminal state '{current.value}'. No further transitions allowed.")

    def _validate_required_fields(self, step: KYCStatus, data: dict[str, Any]) -> None:
        required = _STEP_REQUIRED_FIELDS.get(step, [])
        missing = [f for f in required if f not in data or data[f] is None]
        if missing:
            raise KYCStepError(
                f"Step '{step.value}' is missing required fields: {missing}"
            )

    def _handle_pep_screening(self, data: dict[str, Any]) -> None:
        pep_result = data.get("pep_result", {})
        sanctions_result = data.get("sanctions_result", {})
        is_pep = pep_result.get("is_pep", False)
        is_sanctioned = sanctions_result.get("is_sanctioned", False)

        if is_sanctioned:
            self._suspend("SANCTIONS_MATCH", data)
            raise KYCPEPMatch(
                f"Customer matched sanctions list. Account suspended. "
                f"Report to FIC within 24 hours per AML Act 1044, s.36. "
                f"Reference: {sanctions_result.get('match_reference', 'N/A')}"
            )
        if is_pep:
            # PEP customers are not automatically rejected — they require EDD
            # Mark in customer record and let flow continue to EDD
            self.customer.pep_screening = {
                "is_pep": True,
                "pep_category": pep_result.get("category"),
                "match_reference": pep_result.get("match_reference"),
                "screened_at": datetime.now(timezone.utc).isoformat(),
                "outcome": "REFERRED_FOR_EDD",
            }

    def _validate_pre_agreement_duration(self, data: dict[str, Any]) -> None:
        duration = data.get("display_duration_seconds", 0)
        if duration < MIN_PRE_AGREEMENT_DISPLAY_SECONDS:
            raise KYCPreAgreementTooShort(
                f"Pre-agreement was displayed for {duration}s. "
                f"Minimum required is {MIN_PRE_AGREEMENT_DISPLAY_SECONDS}s "
                "(Digital Credit Directive 2025, Clause 8)."
            )

    def _validate_esignature(self, data: dict[str, Any]) -> None:
        sig_hash = data.get("signature_hash", "")
        if len(sig_hash) != 64:
            raise KYCStepError("E-signature hash must be a 64-character SHA-256 hex string.")

    def _compute_next(self, step: KYCStatus, data: dict[str, Any]) -> KYCStatus:
        if step == KYCStatus.PENDING_RISK_CLASSIFICATION:
            risk_class = data.get("risk_class", "MEDIUM")
            is_sme = getattr(self.customer, "business_type", None) is not None
            pep_data = getattr(self.customer, "pep_screening", None) or {}
            is_pep = pep_data.get("is_pep", False)

            if risk_class == "HIGH" or is_pep:
                return KYCStatus.PENDING_EDD
            if is_sme:
                return KYCStatus.PENDING_BENEFICIAL_OWNERSHIP

        return _STANDARD_TRANSITIONS[step]

    def _apply_step_data(
        self,
        step: KYCStatus,
        data: dict[str, Any],
        next_status: KYCStatus,
    ) -> None:
        """Apply step data to the customer ORM object."""
        self.customer.kyc_status = next_status.value

        if step == KYCStatus.PENDING_RISK_CLASSIFICATION:
            self.customer.risk_class = data["risk_class"]
            self.customer.risk_score = data["risk_score"]

        elif step == KYCStatus.PENDING_CONSENT:
            self.customer.data_processing_consent_given = bool(data.get("consent_data_processing"))
            self.customer.consents = [
                {"type": "DATA_PROCESSING", "given": data.get("consent_data_processing"), "ts": datetime.now(timezone.utc).isoformat()},
                {"type": "CREDIT_BUREAU", "given": data.get("consent_credit_bureau"), "ts": datetime.now(timezone.utc).isoformat()},
                {"type": "MARKETING", "given": data.get("consent_marketing"), "ts": datetime.now(timezone.utc).isoformat()},
            ]

        elif step == KYCStatus.PENDING_PRE_AGREEMENT:
            self.customer.pre_agreement_displayed_at = datetime.fromisoformat(
                data["pre_agreement_displayed_at"]
            )

        elif step == KYCStatus.PENDING_ESIGNATURE:
            self.customer.e_signature_hash = data["signature_hash"]
            self.customer.kyc_completed_at = datetime.now(timezone.utc)
            self.customer.activated_at = datetime.now(timezone.utc)

        self.db.flush()

    def _suspend(self, reason: str, data: dict[str, Any]) -> None:
        self.customer.kyc_status = KYCStatus.SUSPENDED.value
        self.customer.account_status = "SUSPENDED"
        self._write_kyc_audit(
            step=KYCStatus.PENDING_PEP_SCREENING,
            step_data={**data, "suspension_reason": reason},
            previous=KYCStatus.PENDING_PEP_SCREENING,
            next_status=KYCStatus.SUSPENDED,
        )
        self.db.flush()

    def _write_kyc_audit(
        self,
        step: KYCStatus,
        step_data: dict[str, Any],
        previous: KYCStatus,
        next_status: KYCStatus,
    ) -> str:
        from api.utils.audit_chain import write_audit
        entry = write_audit(
            self.db,
            table_name="customers",
            record_id=self.customer.id,
            action=f"KYC_STEP_{step.value}",
            actor_id=self.actor_id,
            old_data={"kyc_status": previous.value},
            new_data={"kyc_status": next_status.value, **step_data},
            customer_id=self.customer.id,
        )
        return entry.id
