"""
Savings account router — deposits, withdrawals, statements.
All transactions run through AML engine (AML Act 1044 ss.22/36).
"""
from __future__ import annotations

import logging
from datetime import datetime
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api import models
from api.compliance.aml_engine import AMLEngine
from api.database import get_db
from api.deps import get_current_customer, get_current_user, require_roles
from api.schemas.savings import (
    DepositRequest,
    SavingsAccountCreate,
    SavingsAccountResponse,
    SavingsProductCreate,
    SavingsProductResponse,
    SavingsStatementResponse,
    SavingsTransactionResponse,
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


# ── Customer self-service routes MUST come before /{account_id} ──────────────
# FastAPI matches in definition order; /my/* would be caught by /{account_id}
# if the dynamic route is registered first.

@router.get("/my/accounts", response_model=list[SavingsAccountResponse],
            summary="Customer's savings accounts (mobile)")
def my_savings(
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    return db.query(models.SavingsAccount).filter_by(customer_id=current_customer.id).all()


@router.post("/my/deposit", response_model=SavingsTransactionResponse, status_code=201,
             summary="Customer self-service deposit via mobile money")
def customer_deposit(
    body: DepositRequest,
    db: Session = Depends(get_db),
    current_customer: models.Customer = Depends(get_current_customer),
):
    account = db.query(models.SavingsAccount).filter_by(
        customer_id=current_customer.id, status="ACTIVE"
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="No active savings account found")

    txn = _post_transaction(
        db=db, account=account, txn_type="DEPOSIT",
        amount=body.amount_ghs, channel=body.channel or "MOBILE_MONEY",
        mno_reference=body.mno_reference, narration=body.narration,
        processed_by=current_customer.id,
    )
    db.commit()
    _run_aml(db=db, account=account, txn=txn, actor_id=current_customer.id)
    write_audit(db, table_name="savings_transactions", record_id=txn.id, action="CUSTOMER_DEPOSIT",
                actor_id=current_customer.id, data={"amount": str(body.amount_ghs)})
    return txn


@router.post("/my/withdraw", response_model=SavingsTransactionResponse, status_code=201,
             summary="Customer self-service withdrawal to mobile money")
def customer_withdraw(
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

    txn = _post_transaction(
        db=db, account=account, txn_type="WITHDRAWAL",
        amount=body.amount_ghs, channel=body.channel or "MOBILE_MONEY",
        narration=body.narration, processed_by=current_customer.id,
    )
    db.commit()
    _run_aml(db=db, account=account, txn=txn, actor_id=current_customer.id)
    write_audit(db, table_name="savings_transactions", record_id=txn.id, action="CUSTOMER_WITHDRAWAL",
                actor_id=current_customer.id, data={"amount": str(body.amount_ghs)})
    return txn


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

    q = db.query(models.SavingsTransaction).filter_by(account_id=account.id)
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


@router.get("/{account_id}", response_model=SavingsAccountResponse,
            summary="Get savings account (staff)")
def get_savings_account(
    account_id: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return _get_account_or_404(db, account_id)


@router.post("/{account_id}/deposit", response_model=SavingsTransactionResponse,
             status_code=201, summary="Post a deposit")
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
             status_code=201, summary="Post a withdrawal")
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
            summary="Account statement")
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
