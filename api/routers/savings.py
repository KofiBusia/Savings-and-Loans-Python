"""
Savings account router — deposits, withdrawals, statements.
All transactions run through AML engine (AML Act 1044 ss.22/36).

Deposit flow  : Customer initiates → Paystack popup → webhook confirms → balance posted.
Withdrawal flow: Customer requests → admin approves/rejects → balance debited on approval.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from api import models
from api.compliance.aml_engine import AMLEngine
from api.config import settings
from api.database import get_db
from api.deps import get_current_customer, get_current_user, require_roles
from api.integrations.payment_gateway import paystack_gateway
from api.schemas.savings import (
    ApprovalDecision,
    DepositInitiateResponse,
    DepositRequest,
    SavingsAccountCreate,
    SavingsAccountResponse,
    SavingsProductCreate,
    SavingsProductResponse,
    SavingsStatementResponse,
    SavingsTransactionResponse,
    WithdrawalApprovalResponse,
    WithdrawalRequest,
)
from api.security import generate_account_number, generate_reference
from api.utils.audit_chain import write_audit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/savings", tags=["Savings"])


@router.post("", response_model=SavingsAccountResponse, status_code=201,
             summary="Open a savings account")
def create_savings_account(
    body: SavingsAccountCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    customer = _get_customer_or_404(db, body.customer_id)

    account = models.SavingsAccount(
        customer_id=customer.id,
        account_number=generate_account_number("SAV"),
        product_name=body.product_name,
        interest_rate_pa=body.interest_rate_pa,
        minimum_balance=body.minimum_balance,
        status="ACTIVE",
    )
    db.add(account)
    db.flush()

    if body.initial_deposit_ghs > 0:
        _post_transaction(
            db=db,
            account=account,
            txn_type="DEPOSIT",
            amount=body.initial_deposit_ghs,
            channel="CASH",
            narration="Opening deposit",
            processed_by=current_user.id,
        )

    db.commit()
    write_audit(db, table_name="savings_accounts", record_id=account.id, action="OPEN",
                actor_id=current_user.id, data={"account_number": account.account_number})

    return account


# ── Product routes — MUST come before /{account_id} ──────────────────────────

@router.get("/products", response_model=list[SavingsProductResponse],
            summary="List all savings products (admin)")
def list_savings_products(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return db.query(models.SavingsProduct).order_by(models.SavingsProduct.name).all()


@router.post("/products", response_model=SavingsProductResponse, status_code=201,
             summary="Create savings product (admin)")
def create_savings_product(
    body: SavingsProductCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("ADMIN", "SUPER_ADMIN")),
):
    if db.query(models.SavingsProduct).filter_by(name=body.name).first():
        raise HTTPException(status_code=409, detail="Product name already exists")
    product = models.SavingsProduct(
        name=body.name,
        description=body.description,
        interest_rate_pa=body.interest_rate_pa,
        minimum_balance=body.minimum_balance,
        minimum_deposit=body.minimum_deposit,
        lock_period_days=body.lock_period_days,
        is_active=body.is_active,
        created_by=current_user.id,
    )
    db.add(product)
    db.commit()
    write_audit(db, table_name="savings_products", record_id=product.id, action="CREATE",
                actor_id=current_user.id, data={"name": body.name})
    return product


@router.get("/products/available", response_model=list[SavingsProductResponse],
            summary="List active savings products (customers)")
def list_available_savings_products(db: Session = Depends(get_db)):
    return db.query(models.SavingsProduct).filter_by(is_active=True).order_by(models.SavingsProduct.name).all()


# ── Paystack webhook — public, no auth ───────────────────────────────────────

@router.post("/paystack/webhook", include_in_schema=False)
async def paystack_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    signature = request.headers.get("x-paystack-signature", "")

    if not paystack_gateway.verify_webhook(payload, signature):
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    try:
        event = json.loads(payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if event.get("event") == "charge.success":
        reference = event.get("data", {}).get("reference", "")
        _confirm_paystack_deposit(db, reference)

    return {"status": "ok"}


# ── Customer self-service routes MUST come before /{account_id} ──────────────

@router.get("/my/accounts", response_model=list[SavingsAccountResponse],
            summary="Customer's savings accounts")
def my_savings(
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    return db.query(models.SavingsAccount).filter_by(customer_id=current_customer.id).all()


@router.post("/my/deposit/initiate", response_model=DepositInitiateResponse,
             status_code=201, summary="Initiate a Paystack deposit (customer)")
def customer_initiate_deposit(
    body: DepositRequest,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    account = (
        db.query(models.SavingsAccount)
        .filter(
            models.SavingsAccount.customer_id == current_customer.id,
            models.SavingsAccount.status.in_(["ACTIVE", "PENDING_ACTIVATION"]),
        )
        .first()
    )
    if not account:
        raise HTTPException(
            status_code=404,
            detail="No savings account found. Please visit a branch to open one.",
        )
    # Customer passed authentication — auto-activate if account still pending
    if account.status == "PENDING_ACTIVATION":
        account.status = "ACTIVE"
        db.flush()

    reference = generate_reference()

    # Create a PENDING transaction — balance is NOT updated yet
    txn = models.SavingsTransaction(
        account_id=account.id,
        reference=reference,
        type="DEPOSIT",
        amount=body.amount_ghs,
        balance_before=account.balance,
        balance_after=account.balance,   # no change until confirmed
        channel="PAYSTACK",
        narration=body.narration or "Online deposit via Paystack",
        paystack_reference=reference,
        status="PENDING",
    )
    db.add(txn)
    db.commit()

    write_audit(db, table_name="savings_transactions", record_id=txn.id,
                action="DEPOSIT_INITIATED", actor_id=current_customer.id,
                data={"amount": str(body.amount_ghs), "reference": reference})
    db.commit()

    return DepositInitiateResponse(
        reference=reference,
        amount_ghs=body.amount_ghs,
        amount_pesewas=int(body.amount_ghs * 100),
        email=current_customer.email or f"{current_customer.id}@crestline.gh",
        public_key=settings.paystack_public_key,
        transaction_id=txn.id,
    )


@router.get("/my/deposit/verify/{reference}", summary="Verify a Paystack deposit (customer)")
async def customer_verify_deposit(
    reference: str,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    txn = db.query(models.SavingsTransaction).filter_by(
        paystack_reference=reference
    ).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")

    account = db.query(models.SavingsAccount).filter_by(id=txn.account_id).first()
    if not account or account.customer_id != current_customer.id:
        raise HTTPException(status_code=403, detail="Not your transaction")

    if txn.status == "CONFIRMED":
        return {"status": "CONFIRMED", "amount_ghs": str(txn.amount), "balance": str(account.balance)}

    # Ask Paystack directly whether payment succeeded
    try:
        result = await paystack_gateway.verify(reference)
        if result.success:
            _confirm_paystack_deposit(db, reference)
            # Re-fetch account to get updated balance
            db.refresh(account)
            return {"status": "CONFIRMED", "amount_ghs": str(txn.amount), "balance": str(account.balance)}
    except Exception:
        log.exception("paystack_verify_failed ref=%s", reference)

    return {"status": txn.status, "amount_ghs": str(txn.amount)}


@router.post("/my/withdraw", response_model=WithdrawalApprovalResponse, status_code=201,
             summary="Request a withdrawal — requires admin approval")
def customer_request_withdrawal(
    body: WithdrawalRequest,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    account = db.query(models.SavingsAccount).filter_by(
        customer_id=current_customer.id, status="ACTIVE"
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="No active savings account found")

    available = account.balance - account.locked_amount - account.minimum_balance
    if body.amount_ghs > available:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds. Available: GHS {available:.2f}",
        )

    # Don't debit yet — create a pending approval
    approval = models.WithdrawalApproval(
        account_id=account.id,
        customer_id=current_customer.id,
        amount_ghs=body.amount_ghs,
        channel=body.channel or "MOBILE_MONEY",
        destination_account=body.destination_account,
        narration=body.narration,
        status="PENDING",
    )
    db.add(approval)
    db.commit()

    write_audit(db, table_name="withdrawal_approvals", record_id=approval.id,
                action="WITHDRAWAL_REQUESTED", actor_id=current_customer.id,
                data={"amount": str(body.amount_ghs)})

    return approval


@router.get("/my/withdrawals", response_model=list[WithdrawalApprovalResponse],
            summary="Customer's withdrawal requests")
def my_withdrawals(
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    return (
        db.query(models.WithdrawalApproval)
        .filter_by(customer_id=current_customer.id)
        .order_by(models.WithdrawalApproval.requested_at.desc())
        .all()
    )


@router.get("/my/statement", response_model=SavingsStatementResponse,
            summary="Customer's own account statement")
def my_statement(
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    account = db.query(models.SavingsAccount).filter_by(
        customer_id=current_customer.id, status="ACTIVE"
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="No active savings account found")

    q = db.query(models.SavingsTransaction).filter(
        models.SavingsTransaction.account_id == account.id,
        models.SavingsTransaction.status == "CONFIRMED",
    )
    if from_date:
        q = q.filter(models.SavingsTransaction.created_at >= from_date)
    if to_date:
        q = q.filter(models.SavingsTransaction.created_at <= to_date)

    total = q.count()
    transactions = q.order_by(models.SavingsTransaction.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()

    return SavingsStatementResponse(
        account_number=account.account_number,
        balance=account.balance,
        from_date=from_date,
        to_date=to_date,
        total_transactions=total,
        transactions=transactions,
    )


@router.get("/my/statement/pdf", response_class=HTMLResponse,
            summary="Customer account statement as printable HTML/PDF")
def my_statement_pdf(
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    account = db.query(models.SavingsAccount).filter_by(
        customer_id=current_customer.id, status="ACTIVE"
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="No active savings account found")

    q = db.query(models.SavingsTransaction).filter(
        models.SavingsTransaction.account_id == account.id,
        models.SavingsTransaction.status == "CONFIRMED",
    )
    if from_date:
        q = q.filter(models.SavingsTransaction.created_at >= from_date)
    if to_date:
        q = q.filter(models.SavingsTransaction.created_at <= to_date)

    txns = q.order_by(models.SavingsTransaction.created_at.asc()).all()
    from_label = from_date.strftime("%d %b %Y") if from_date else "Inception"
    to_label = to_date.strftime("%d %b %Y") if to_date else datetime.utcnow().strftime("%d %b %Y")
    generated_at = datetime.utcnow().strftime("%d %b %Y %H:%M UTC")

    rows_html = ""
    for t in txns:
        cr = f"GHS {t.amount:,.2f}" if t.type in ("DEPOSIT", "INTEREST") else ""
        dr = f"GHS {t.amount:,.2f}" if t.type not in ("DEPOSIT", "INTEREST") else ""
        rows_html += f"""<tr>
          <td>{t.created_at.strftime('%d/%m/%Y')}</td>
          <td>{t.reference}</td>
          <td>{t.narration or t.type}</td>
          <td style="color:#2e7d32;text-align:right;">{cr}</td>
          <td style="color:#c62828;text-align:right;">{dr}</td>
          <td style="text-align:right;">GHS {t.balance_after:,.2f}</td>
        </tr>"""

    if not rows_html:
        rows_html = '<tr><td colspan="6" style="text-align:center;color:#888;">No transactions in this period</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Account Statement — {account.account_number}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 12px; color: #1a1a1a; background: #fff; }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 32px; }}
  .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; border-bottom: 3px solid #c9a227; padding-bottom: 16px; }}
  .logo-text {{ font-size: 22px; font-weight: 700; color: #1a1a1a; }}
  .logo-sub {{ font-size: 10px; color: #555; margin-top: 2px; }}
  .doc-title {{ font-size: 16px; font-weight: 700; text-align: right; color: #c9a227; }}
  .doc-sub {{ font-size: 10px; color: #555; text-align: right; margin-top: 4px; }}
  .meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; background: #f9f6ee; border: 1px solid #e8ddb5; border-radius: 6px; padding: 14px; }}
  .meta dt {{ font-size: 10px; color: #777; text-transform: uppercase; letter-spacing: 0.5px; }}
  .meta dd {{ font-size: 12px; font-weight: 600; margin-top: 2px; }}
  .balance-box {{ background: #c9a227; color: #fff; border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
  .balance-box .lbl {{ font-size: 11px; opacity: 0.85; }}
  .balance-box .val {{ font-size: 20px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
  thead tr {{ background: #1a1a1a; color: #fff; }}
  thead th {{ padding: 8px 6px; text-align: left; }}
  tbody tr:nth-child(even) {{ background: #f7f7f7; }}
  tbody td {{ padding: 7px 6px; border-bottom: 1px solid #eee; }}
  .footer {{ margin-top: 24px; font-size: 10px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ font-size: 11px; }}
    .page {{ padding: 16px; max-width: 100%; }}
  }}
</style>
</head>
<body>
<div class="page">
  <div class="no-print" style="text-align:right;margin-bottom:16px;">
    <button onclick="window.print()" style="background:#c9a227;color:#fff;border:none;padding:8px 20px;border-radius:4px;font-size:13px;cursor:pointer;">&#128438; Download / Print PDF</button>
    <button onclick="window.close()" style="background:#555;color:#fff;border:none;padding:8px 16px;border-radius:4px;font-size:13px;cursor:pointer;margin-left:8px;">Close</button>
  </div>

  <div class="header">
    <div>
      <div class="logo-text">{settings.institution_name}</div>
      <div class="logo-sub">Licence: {settings.bog_licence_number}</div>
    </div>
    <div>
      <div class="doc-title">ACCOUNT STATEMENT</div>
      <div class="doc-sub">Generated: {generated_at}</div>
    </div>
  </div>

  <dl class="meta">
    <div><dt>Account Number</dt><dd>{account.account_number}</dd></div>
    <div><dt>Account Name</dt><dd>{current_customer.first_name} {current_customer.last_name}</dd></div>
    <div><dt>Product</dt><dd>{account.product_name}</dd></div>
    <div><dt>Statement Period</dt><dd>{from_label} – {to_label}</dd></div>
    <div><dt>Phone</dt><dd>{current_customer.phone_e164 or '—'}</dd></div>
    <div><dt>Interest Rate</dt><dd>{float(account.interest_rate_pa)*100:.2f}% p.a.</dd></div>
  </dl>

  <div class="balance-box">
    <div><div class="lbl">Current Balance</div><div class="val">GHS {account.balance:,.2f}</div></div>
    <div style="text-align:right;"><div class="lbl">Total Transactions</div><div class="val">{len(txns)}</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>Reference</th>
        <th>Description</th>
        <th style="text-align:right;">Credit</th>
        <th style="text-align:right;">Debit</th>
        <th style="text-align:right;">Balance</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div class="footer">
    This statement is computer-generated and requires no signature. For queries contact us at {settings.fic_reporting_officer.replace('compliance@', 'support@')}.
    {settings.institution_name} is licensed by the Bank of Ghana under licence {settings.bog_licence_number}.
  </div>
</div>
</body>
</html>"""
    return HTMLResponse(content=html)


# ── Admin: Withdrawal approvals ───────────────────────────────────────────────

@router.get("/withdrawals/pending", response_model=list[WithdrawalApprovalResponse],
            summary="List pending withdrawal requests (admin)")
def list_pending_withdrawals(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    return (
        db.query(models.WithdrawalApproval)
        .filter_by(status="PENDING")
        .order_by(models.WithdrawalApproval.requested_at.asc())
        .all()
    )


@router.get("/withdrawals/all", response_model=list[WithdrawalApprovalResponse],
            summary="List all withdrawal requests (admin)")
def list_all_withdrawals(
    approval_status: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    q = db.query(models.WithdrawalApproval)
    if approval_status:
        q = q.filter_by(status=approval_status)
    return (
        q.order_by(models.WithdrawalApproval.requested_at.desc())
        .offset((page - 1) * page_size).limit(page_size).all()
    )


@router.post("/withdrawals/{approval_id}/approve", response_model=WithdrawalApprovalResponse,
             summary="Approve a withdrawal request (admin)")
def approve_withdrawal(
    approval_id: str,
    body: ApprovalDecision,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    approval = _get_approval_or_404(db, approval_id)
    if approval.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request is already {approval.status}")

    account = _get_active_account_or_404(db, approval.account_id)
    available = account.balance - account.locked_amount - account.minimum_balance
    if approval.amount_ghs > available:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds at time of approval. Available: GHS {available:.2f}",
        )

    txn = _post_transaction(
        db=db,
        account=account,
        txn_type="WITHDRAWAL",
        amount=approval.amount_ghs,
        channel=approval.channel or "MOBILE_MONEY",
        narration=approval.narration,
        processed_by=current_user.id,
    )

    approval.status = "APPROVED"
    approval.reviewed_by = current_user.id
    approval.reviewed_at = datetime.utcnow()
    approval.review_note = body.note
    approval.transaction_id = txn.id
    db.commit()

    _run_aml(db=db, account=account, txn=txn, actor_id=current_user.id)
    write_audit(db, table_name="withdrawal_approvals", record_id=approval.id,
                action="WITHDRAWAL_APPROVED", actor_id=current_user.id,
                data={"amount": str(approval.amount_ghs), "note": body.note})

    return approval


@router.post("/withdrawals/{approval_id}/reject", response_model=WithdrawalApprovalResponse,
             summary="Reject a withdrawal request (admin)")
def reject_withdrawal(
    approval_id: str,
    body: ApprovalDecision,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    approval = _get_approval_or_404(db, approval_id)
    if approval.status != "PENDING":
        raise HTTPException(status_code=400, detail=f"Request is already {approval.status}")

    approval.status = "REJECTED"
    approval.reviewed_by = current_user.id
    approval.reviewed_at = datetime.utcnow()
    approval.review_note = body.note
    db.commit()

    write_audit(db, table_name="withdrawal_approvals", record_id=approval.id,
                action="WITHDRAWAL_REJECTED", actor_id=current_user.id,
                data={"amount": str(approval.amount_ghs), "note": body.note})

    return approval


# ── Staff deposit/withdraw (direct, no Paystack) ──────────────────────────────

@router.get("/{account_id}", response_model=SavingsAccountResponse,
            summary="Get savings account (staff)")
def get_savings_account(
    account_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return _get_account_or_404(db, account_id)


@router.post("/{account_id}/deposit", response_model=SavingsTransactionResponse,
             status_code=201, summary="Post a cash/teller deposit (staff)")
def deposit(
    account_id: str,
    body: DepositRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("TELLER", "FIELD_OFFICER", "ADMIN", "SUPER_ADMIN")),
):
    account = _get_active_account_or_404(db, account_id)

    txn = _post_transaction(
        db=db,
        account=account,
        txn_type="DEPOSIT",
        amount=body.amount_ghs,
        channel=body.channel,
        mno_reference=body.mno_reference,
        narration=body.narration,
        processed_by=current_user.id,
    )
    db.commit()

    _run_aml(db=db, account=account, txn=txn, actor_id=current_user.id)

    write_audit(db, table_name="savings_transactions", record_id=txn.id, action="DEPOSIT",
                actor_id=current_user.id, data={"amount": str(body.amount_ghs)})

    return txn


@router.post("/{account_id}/withdraw", response_model=SavingsTransactionResponse,
             status_code=201, summary="Post a withdrawal (staff-approved)")
def withdraw(
    account_id: str,
    body: WithdrawalRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_roles("TELLER", "ADMIN", "SUPER_ADMIN")),
):
    account = _get_active_account_or_404(db, account_id)

    available = account.balance - account.locked_amount - account.minimum_balance
    if body.amount_ghs > available:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient funds. Available: GHS {available:.2f}",
        )

    txn = _post_transaction(
        db=db,
        account=account,
        txn_type="WITHDRAWAL",
        amount=body.amount_ghs,
        channel=body.channel,
        narration=body.narration,
        processed_by=current_user.id,
    )
    db.commit()

    _run_aml(db=db, account=account, txn=txn, actor_id=current_user.id)

    write_audit(db, table_name="savings_transactions", record_id=txn.id, action="WITHDRAWAL",
                actor_id=current_user.id, data={"amount": str(body.amount_ghs)})

    return txn


@router.get("/{account_id}/statement", response_model=SavingsStatementResponse,
            summary="Account statement (staff)")
def statement(
    account_id: str,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    account = _get_account_or_404(db, account_id)

    q = db.query(models.SavingsTransaction).filter_by(account_id=account_id)
    if from_date:
        q = q.filter(models.SavingsTransaction.created_at >= from_date)
    if to_date:
        q = q.filter(models.SavingsTransaction.created_at <= to_date)

    total = q.count()
    transactions = q.order_by(models.SavingsTransaction.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()

    return SavingsStatementResponse(
        account_number=account.account_number,
        balance=account.balance,
        from_date=from_date,
        to_date=to_date,
        total_transactions=total,
        transactions=transactions,
    )


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _confirm_paystack_deposit(db: Session, reference: str) -> None:
    txn = db.query(models.SavingsTransaction).filter_by(
        paystack_reference=reference, status="PENDING"
    ).first()
    if not txn:
        return   # already confirmed or not found

    account = db.query(models.SavingsAccount).filter_by(id=txn.account_id).first()
    if not account:
        return

    account.balance += txn.amount
    account.last_transaction_at = datetime.utcnow()
    txn.balance_after = account.balance
    txn.status = "CONFIRMED"
    db.commit()

    _run_aml(db=db, account=account, txn=txn, actor_id=account.customer_id)
    log.info("paystack_deposit_confirmed ref=%s amount=%s account=%s",
             reference, txn.amount, account.account_number)


def _post_transaction(
    db: Session,
    account: models.SavingsAccount,
    txn_type: str,
    amount: Decimal,
    channel: str = "CASH",
    mno_reference: str | None = None,
    narration: str | None = None,
    processed_by: str | None = None,
) -> models.SavingsTransaction:
    balance_before = account.balance
    if txn_type in ("DEPOSIT", "INTEREST_CREDIT", "TRANSFER_IN"):
        account.balance += amount
    else:
        account.balance -= amount

    account.last_transaction_at = datetime.utcnow()

    txn = models.SavingsTransaction(
        account_id=account.id,
        reference=generate_reference(),
        type=txn_type,
        amount=amount,
        balance_before=balance_before,
        balance_after=account.balance,
        channel=channel,
        mno_reference=mno_reference,
        narration=narration,
        processed_by=processed_by,
        status="CONFIRMED",
    )
    db.add(txn)
    return txn


def _run_aml(db: Session, account: models.SavingsAccount,
             txn: models.SavingsTransaction, actor_id: str) -> None:
    try:
        customer = db.query(models.Customer).filter_by(id=account.customer_id).first()
        if customer:
            AMLEngine(db=db).process_transaction(
                customer=customer,
                transaction={"id": txn.id, "type": txn.type, "amount": txn.amount},
                actor_id=actor_id,
            )
    except Exception:
        log.exception("aml_check_failed txn_id=%s", txn.id)


def _get_account_or_404(db: Session, account_id: str) -> models.SavingsAccount:
    account = db.query(models.SavingsAccount).filter_by(id=account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Savings account not found")
    return account


def _get_active_account_or_404(db: Session, account_id: str) -> models.SavingsAccount:
    account = _get_account_or_404(db, account_id)
    if account.status != "ACTIVE":
        raise HTTPException(status_code=400, detail=f"Account is {account.status}, not ACTIVE")
    return account


def _get_customer_or_404(db: Session, customer_id: str) -> models.Customer:
    customer = db.query(models.Customer).filter_by(id=customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


def _get_approval_or_404(db: Session, approval_id: str) -> models.WithdrawalApproval:
    approval = db.query(models.WithdrawalApproval).filter_by(id=approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")
    return approval
