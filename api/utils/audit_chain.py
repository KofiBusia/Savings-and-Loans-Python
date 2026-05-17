"""
Immutable SHA-256 Hash-Chained Audit Log
Regulatory anchor: Cybersecurity Act 2020 (Act 1038), Section 34
"Financial institutions shall maintain tamper-evident audit records."

Design:
  Each audit log record stores:
    - hash         = SHA-256(table | record_id | action | actor_id | data | previous_hash)
    - previous_hash = hash of the immediately preceding record (or 'GENESIS' for first)

  Any modification to any historical record breaks the chain.
  verify_chain() re-computes all hashes and detects tampering.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session


# ─── Exceptions ───────────────────────────────────────────────────────────────

class AuditChainTampered(RuntimeError):
    """Raised when audit log hash chain integrity check fails.

    Under Cybersecurity Act 2020 s.34, this constitutes a reportable incident.
    """


# ─── Hash Computation ─────────────────────────────────────────────────────────

def _compute_hash(
    table_name: str,
    record_id: str,
    action: str,
    actor_id: str,
    data: dict[str, Any],
    previous_hash: str,
) -> str:
    """Compute the SHA-256 hash for one audit record."""
    payload = (
        f"{table_name}|{record_id}|{action}|{actor_id}|"
        f"{json.dumps(data, sort_keys=True, default=str)}|{previous_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ─── Write Audit Entry ────────────────────────────────────────────────────────

def write_audit(
    db: Session,
    *,
    table_name: str,
    record_id: str,
    action: str,
    actor_id: str,
    data: dict[str, Any] | None = None,
    actor_type: str | None = None,
    ip_address: str | None = None,
    # legacy / unused kwargs kept for call-site compatibility
    old_data: dict[str, Any] | None = None,
    new_data: dict[str, Any] | None = None,
    customer_id: str | None = None,
) -> "AuditLog":  # type: ignore[name-defined]
    """Write one tamper-evident audit entry to the database.

    This function is the ONLY authorised way to create audit records.
    Returns the created AuditLog ORM object.
    """
    from api.models import AuditLog

    # Normalise data from all aliases
    effective_data: dict[str, Any] = data or new_data or {}

    # Get previous hash (most recent record)
    previous = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    previous_hash = previous.hash if previous else "GENESIS"

    record_hash = _compute_hash(
        table_name=table_name,
        record_id=record_id,
        action=action,
        actor_id=actor_id,
        data=effective_data,
        previous_hash=previous_hash,
    )

    entry = AuditLog(
        id=str(uuid4()),
        table_name=table_name,
        record_id=record_id,
        action=action,
        actor_id=actor_id,
        actor_type=actor_type or "USER",
        data=effective_data,
        ip_address=ip_address,
        previous_hash=previous_hash,
        hash=record_hash,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
    return entry


# ─── Verify Chain Integrity ───────────────────────────────────────────────────

def verify_chain(db: Session) -> dict[str, Any]:
    """Re-compute every hash in the audit chain and verify linkage.

    Returns a summary dict with:
      - total: number of records checked
      - ok: True if chain is intact
      - first_tampered_id: ID of first broken record (None if ok)
      - tampered_count: number of broken records

    Raises AuditChainTampered immediately on first detected break.
    """
    from api.models import AuditLog

    records = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.asc())
        .all()
    )

    if not records:
        return {"total": 0, "ok": True, "first_tampered_id": None, "tampered_count": 0}

    tampered_count = 0
    first_tampered_id = None
    previous_hash = "GENESIS"

    for record in records:
        if record.previous_hash != previous_hash:
            tampered_count += 1
            if first_tampered_id is None:
                first_tampered_id = record.id

        expected_hash = _compute_hash(
            table_name=record.table_name,
            record_id=record.record_id,
            action=record.action,
            actor_id=record.actor_id,
            data=record.data or {},
            previous_hash=record.previous_hash,
        )
        if expected_hash != record.hash:
            tampered_count += 1
            if first_tampered_id is None:
                first_tampered_id = record.id

        previous_hash = record.hash

    if tampered_count > 0:
        raise AuditChainTampered(
            f"Audit chain integrity violation: {tampered_count} record(s) tampered. "
            f"First affected record ID: {first_tampered_id}. "
            "This is a reportable incident under Cybersecurity Act 2020 s.34."
        )

    return {
        "total": len(records),
        "ok": True,
        "first_tampered_id": None,
        "tampered_count": 0,
    }


# ─── Export for BoG Examination ───────────────────────────────────────────────

def export_audit_range(
    db: Session,
    *,
    from_date: datetime,
    to_date: datetime,
    table_name: str | None = None,
) -> list[dict[str, Any]]:
    """Export audit records for a date range (BoG examination use).

    Always verifies chain before export to ensure integrity.
    Raises AuditChainTampered if chain is broken.
    """
    verify_chain(db)

    from api.models import AuditLog

    q = db.query(AuditLog).filter(
        AuditLog.created_at >= from_date,
        AuditLog.created_at <= to_date,
    )
    if table_name:
        q = q.filter(AuditLog.table_name == table_name)

    return [
        {
            "id": r.id,
            "table": r.table_name,
            "record_id": r.record_id,
            "action": r.action,
            "actor_id": r.actor_id,
            "actor_type": r.actor_type,
            "data": r.data,
            "ip_address": r.ip_address,
            "hash": r.hash,
            "previous_hash": r.previous_hash,
            "timestamp": r.created_at.isoformat(),
        }
        for r in q.order_by(AuditLog.created_at.asc()).all()
    ]
