"""
Compliance router — AML alerts, STR/CTR filing, credit bureau, BoG reports.
Access restricted to COMPLIANCE_OFFICER and SUPER_ADMIN.
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api import models
from api.compliance.aml_engine import AMLEngine
from api.config import settings
from api.database import get_db
from api.deps import get_current_user, require_mfa, require_roles
from api.schemas.compliance import (
    AMLAlertResponse,
    AMLAlertUpdateRequest,
    AuditChainVerifyResponse,
    AuditLogResponse,
    ComplianceDashboardResponse,
    CreditBureauSubmissionRequest,
    CreditBureauSubmissionResponse,
    CTRFilingRequest,
    FICSubmissionResponse,
    RegulatoryReportResponse,
    STRFilingRequest,
)
from api.utils.audit_chain import export_audit_range, verify_chain, write_audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["Compliance"])

_COMPLIANCE_ROLES = ("COMPLIANCE_OFFICER", "SUPER_ADMIN")


@router.get("/dashboard", response_model=ComplianceDashboardResponse,
            summary="Compliance dashboard KPIs")
def compliance_dashboard(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    open_alerts = db.query(models.AMLAlert).filter_by(status="OPEN").count()
    pending_edd = db.query(models.Customer).filter_by(edd_required=True, edd_completed_at=None).count()

    last_bureau = (
        db.query(models.CreditBureauSubmission)
        .filter_by(status="SUBMITTED")
        .order_by(models.CreditBureauSubmission.submitted_at.desc())
        .first()
    )

    upcoming_reports = (
        db.query(models.RegulatoryReport)
        .filter(
            models.RegulatoryReport.status.in_(["DRAFT", "OVERDUE"]),
            models.RegulatoryReport.deadline.isnot(None),
        )
        .order_by(models.RegulatoryReport.deadline)
        .limit(5)
        .all()
    )

    return ComplianceDashboardResponse(
        open_aml_alerts=open_alerts,
        overdue_ctrs=0,
        overdue_strs=0,
        pending_edd_reviews=pending_edd,
        credit_bureau_last_submitted=last_bureau.submitted_at if last_bureau else None,
        audit_chain_status="UNVERIFIED",
        upcoming_report_deadlines=[
            {"type": r.report_type, "deadline": r.deadline.isoformat(), "status": r.status}
            for r in upcoming_reports
        ],
    )


# ─── AML Alerts ────────────────────────────────────────────────────────────────

@router.get("/aml/alerts", response_model=list[AMLAlertResponse],
            summary="List AML alerts")
def list_aml_alerts(
    status_filter: str | None = Query(default=None, alias="status"),
    alert_type: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    q = db.query(models.AMLAlert)
    if status_filter:
        q = q.filter_by(status=status_filter)
    if alert_type:
        q = q.filter_by(alert_type=alert_type)
    return q.order_by(models.AMLAlert.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()


@router.get("/aml/alerts/{alert_id}", response_model=AMLAlertResponse,
            summary="Get AML alert")
def get_aml_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    alert = db.query(models.AMLAlert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/aml/alerts/{alert_id}", response_model=AMLAlertResponse,
              summary="Update AML alert status")
def update_aml_alert(
    alert_id: str,
    body: AMLAlertUpdateRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    alert = db.query(models.AMLAlert).filter_by(id=alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = body.status
    alert.review_notes = body.review_notes
    alert.reviewed_by = current_user.id
    alert.reviewed_at = datetime.utcnow()
    db.commit()

    write_audit(db, table_name="aml_alerts", record_id=alert.id, action="UPDATE_STATUS",
                actor_id=current_user.id, data={"status": body.status})

    return alert


# ─── STR / CTR Filing ──────────────────────────────────────────────────────────

@router.post("/aml/str", response_model=FICSubmissionResponse,
             summary="File Suspicious Transaction Report (FIC)")
def file_str(
    body: STRFilingRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "COMPLIANCE_OFFICER" not in (current_user.roles or []) and \
       "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires COMPLIANCE_OFFICER or SUPER_ADMIN")

    alert = db.query(models.AMLAlert).filter_by(id=body.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="AML alert not found")

    customer = db.query(models.Customer).filter_by(id=alert.customer_id).first()

    from api.compliance.aml_engine import generate_str_xml
    xml_payload = generate_str_xml(
        customer=customer.__dict__ if customer else {},
        transaction={"id": alert.transaction_id, "amount": str(alert.amount_ghs)},
        reporting_officer=settings.fic_reporting_officer,
        narrative=body.narrative,
    )

    # In production, POST xml_payload to settings.fic_submission_url
    fic_ref = f"STR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{alert.id[:8].upper()}"

    alert.status = "FILED_STR"
    alert.fic_reference = fic_ref
    alert.filed_at = datetime.utcnow()
    db.add(models.RegulatoryReport(
        report_type="STR",
        submitted_at=datetime.utcnow(),
        submitted_by=current_user.id,
        submission_reference=fic_ref,
        status="SUBMITTED",
        submission_payload=xml_payload,
    ))
    db.commit()

    write_audit(db, table_name="aml_alerts", record_id=alert.id, action="FILE_STR",
                actor_id=current_user.id, data={"fic_reference": fic_ref})

    return FICSubmissionResponse(
        fic_reference=fic_ref,
        submitted_at=datetime.utcnow(),
        status="SUBMITTED",
        xml_preview=xml_payload[:500] if xml_payload else None,
    )


@router.post("/aml/ctr", response_model=FICSubmissionResponse,
             summary="File Currency Transaction Report (FIC — threshold GHS 10,000)")
def file_ctr(
    body: CTRFilingRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_mfa),
):
    if "COMPLIANCE_OFFICER" not in (current_user.roles or []) and \
       "SUPER_ADMIN" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Requires COMPLIANCE_OFFICER or SUPER_ADMIN")

    customer = db.query(models.Customer).filter_by(id=body.customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    from api.compliance.aml_engine import generate_ctr_xml
    xml_payload = generate_ctr_xml(
        customer=customer.__dict__,
        transaction={
            "id": body.transaction_id,
            "type": body.transaction_type,
            "amount": str(body.amount_ghs),
            "date": body.transaction_date.isoformat(),
            "channel": body.channel,
        },
        reporting_officer=settings.fic_reporting_officer,
    )

    fic_ref = f"CTR-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{body.transaction_id[:8].upper()}"

    db.add(models.RegulatoryReport(
        report_type="CTR",
        submitted_at=datetime.utcnow(),
        submitted_by=current_user.id,
        submission_reference=fic_ref,
        status="SUBMITTED",
        submission_payload=xml_payload,
    ))
    db.commit()

    write_audit(db, table_name="regulatory_reports", record_id=fic_ref, action="FILE_CTR",
                actor_id=current_user.id, data={"amount": str(body.amount_ghs)})

    return FICSubmissionResponse(
        fic_reference=fic_ref,
        submitted_at=datetime.utcnow(),
        status="SUBMITTED",
        xml_preview=xml_payload[:500] if xml_payload else None,
    )


# ─── Credit Bureau ─────────────────────────────────────────────────────────────

@router.post("/bureau/submit", response_model=list[CreditBureauSubmissionResponse],
             summary="Submit daily credit bureau report (L.I. 2394 Regulation 8)")
async def submit_credit_bureau(
    body: CreditBureauSubmissionRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    from api.integrations.credit_bureaus import CreditBureauManager, CreditRecord
    from decimal import Decimal

    batch_date = body.batch_date or datetime.utcnow()

    # Pull active loans for submission
    active_loans = db.query(models.Loan).filter(
        models.Loan.status.in_(["ACTIVE", "OVERDUE", "DISBURSED"])
    ).limit(1000).all()

    records = []
    for loan in active_loans:
        customer = db.query(models.Customer).filter_by(id=loan.customer_id).first()
        if not customer:
            continue
        records.append(CreditRecord(
            institution_code=settings.ghipss_institution_code,
            account_number=loan.loan_number,
            customer_id=customer.id,
            ghana_card_number=customer.ghana_card_number,
            full_name=f"{customer.first_name} {customer.last_name}",
            phone=customer.phone_e164,
            facility_type="LOAN",
            currency="GHS",
            sanctioned_amount=str(loan.principal_ghs),
            outstanding_amount=str(loan.outstanding_ghs),
            overdue_amount=str(loan.arrears_amount_ghs),
            days_past_due=loan.days_past_due,
            account_status=loan.status,
            opened_date=loan.disbursed_at.strftime("%Y-%m-%d") if loan.disbursed_at else "",
            maturity_date=loan.maturity_date.strftime("%Y-%m-%d") if loan.maturity_date else "",
        ))

    manager = CreditBureauManager()
    results = await manager.submit_daily(records)

    submissions = []
    for result in results:
        sub = models.CreditBureauSubmission(
            batch_date=batch_date,
            bureau=result.bureau,
            record_count=len(records),
            status="SUBMITTED" if result.success else "FAILED",
            submitted_at=datetime.utcnow() if result.success else None,
            submitted_by=current_user.id,
            error=result.error,
        )
        db.add(sub)
        db.flush()
        submissions.append(sub)

    db.commit()
    return submissions


# ─── Audit Chain ───────────────────────────────────────────────────────────────

@router.get("/audit/verify", response_model=AuditChainVerifyResponse,
            summary="Verify SHA-256 audit chain integrity (Cybersecurity Act 2020 s.34)")
def verify_audit_chain(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("AUDIT_VIEWER", *_COMPLIANCE_ROLES)),
):
    try:
        result = verify_chain(db)
        return AuditChainVerifyResponse(
            chain_valid=result["valid"],
            total_records=result["total"],
            verified_at=datetime.utcnow(),
            first_record_id=result.get("first_id"),
            last_record_id=result.get("last_id"),
        )
    except Exception as exc:
        return AuditChainVerifyResponse(
            chain_valid=False,
            total_records=0,
            verified_at=datetime.utcnow(),
            first_record_id=None,
            last_record_id=None,
            error=str(exc),
        )


@router.get("/audit/logs", response_model=list[AuditLogResponse],
            summary="Export audit log range")
def export_audit_logs(
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    table_name: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("AUDIT_VIEWER", *_COMPLIANCE_ROLES)),
):
    return export_audit_range(
        db,
        from_date=from_date,
        to_date=to_date,
        table_name=table_name,
        page=page,
        page_size=page_size,
    )


# ─── BoG Reports ───────────────────────────────────────────────────────────────

@router.get("/reports", response_model=list[RegulatoryReportResponse],
            summary="List regulatory reports")
def list_reports(
    report_type: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles(*_COMPLIANCE_ROLES)),
):
    q = db.query(models.RegulatoryReport)
    if report_type:
        q = q.filter_by(report_type=report_type)
    if status_filter:
        q = q.filter_by(status=status_filter)
    return q.order_by(models.RegulatoryReport.created_at.desc()).limit(100).all()
