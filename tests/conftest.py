"""
pytest fixtures for Ghana Savings & Loans test suite.
Uses an in-memory SQLite database for speed — no PostgreSQL required for unit tests.
Integration tests that need real JSONB/ARRAY should use the CI PostgreSQL service.
"""
from __future__ import annotations

import os
from datetime import datetime
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Force test environment before importing app modules
os.environ.setdefault("NODE_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-production-min-32-chars!")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("MOCK_GHIPSS", "true")
os.environ.setdefault("MOCK_CREDIT_BUREAUS", "true")
os.environ.setdefault("MOCK_GHANA_CARD_API", "true")

from api.database import Base, get_db
from api.models import (
    AuditLog, Customer, Loan, LoanProduct, RefreshToken,
    SavingsAccount, User,
)
from api.security import generate_account_number, hash_password

# ─── Test Database Setup ──────────────────────────────────────────────────────

SQLITE_URL = "sqlite:///:memory:"

_engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)
_TestingSessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    """Create all tables once per test session."""
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)


@pytest.fixture()
def db():
    """Request-scoped database session — rolls back after each test."""
    connection = _engine.connect()
    transaction = connection.begin()
    session = _TestingSessionLocal(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


# ─── App Client ───────────────────────────────────────────────────────────────

@pytest.fixture()
def client(db):
    from app import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db

    with TestClient(app) as c:
        yield c


# ─── Users ────────────────────────────────────────────────────────────────────

@pytest.fixture()
def super_admin(db) -> User:
    user = User(
        email="admin@test.gsl.com.gh",
        password_hash=hash_password("Admin@1234!"),
        full_name="Test Admin",
        roles=["SUPER_ADMIN", "COMPLIANCE_OFFICER", "CREDIT_MANAGER"],
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def field_officer(db) -> User:
    user = User(
        email="officer@test.gsl.com.gh",
        password_hash=hash_password("Officer@1234!"),
        full_name="Test Field Officer",
        roles=["FIELD_OFFICER"],
        is_active=True,
        mfa_enabled=False,
        branch_code="ACCRA-01",
    )
    db.add(user)
    db.commit()
    return user


@pytest.fixture()
def compliance_officer(db) -> User:
    user = User(
        email="compliance@test.gsl.com.gh",
        password_hash=hash_password("Comply@1234!"),
        full_name="Test Compliance Officer",
        roles=["COMPLIANCE_OFFICER"],
        is_active=True,
        mfa_enabled=False,
    )
    db.add(user)
    db.commit()
    return user


# ─── Auth tokens ──────────────────────────────────────────────────────────────

@pytest.fixture()
def admin_token(super_admin: User) -> str:
    from api.security import create_access_token
    return create_access_token(super_admin.id, super_admin.roles, mfa_verified=True)


@pytest.fixture()
def officer_token(field_officer: User) -> str:
    from api.security import create_access_token
    return create_access_token(field_officer.id, field_officer.roles, mfa_verified=False)


@pytest.fixture()
def compliance_token(compliance_officer: User) -> str:
    from api.security import create_access_token
    return create_access_token(compliance_officer.id, compliance_officer.roles, mfa_verified=True)


@pytest.fixture()
def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def officer_headers(officer_token: str) -> dict:
    return {"Authorization": f"Bearer {officer_token}"}


@pytest.fixture()
def compliance_headers(compliance_token: str) -> dict:
    return {"Authorization": f"Bearer {compliance_token}"}


# ─── Customers ────────────────────────────────────────────────────────────────

@pytest.fixture()
def active_customer(db, field_officer: User) -> Customer:
    customer = Customer(
        account_number=generate_account_number(),
        first_name="Kofi",
        last_name="Mensah",
        ghana_card_number="GHA-123456789-5",
        phone_e164="+233244123456",
        mno="MTN",
        password_hash=hash_password("Pass@1234"),
        kyc_status="ACTIVE",
        is_active=True,
        onboarded_by=field_officer.id,
        ghana_card_verified=True,
        risk_level="LOW",
    )
    db.add(customer)
    db.flush()

    db.add(SavingsAccount(
        customer_id=customer.id,
        account_number=generate_account_number("SAV"),
        product_name="Regular Savings",
        balance=Decimal("500.00"),
        status="ACTIVE",
    ))
    db.commit()
    return customer


@pytest.fixture()
def customer_token(active_customer: Customer) -> str:
    from api.security import create_customer_access_token
    return create_customer_access_token(active_customer.id, active_customer.account_number)


@pytest.fixture()
def customer_headers(customer_token: str) -> dict:
    return {"Authorization": f"Bearer {customer_token}"}


# ─── Loan Products ────────────────────────────────────────────────────────────

@pytest.fixture()
def loan_product(db, super_admin: User) -> LoanProduct:
    product = LoanProduct(
        name="Standard Personal Loan",
        annual_interest_rate=Decimal("0.24"),  # 24% p.a. — simple interest
        processing_fee_pct=Decimal("0.02"),
        min_amount_ghs=Decimal("500"),
        max_amount_ghs=Decimal("50000"),
        min_tenure_months=3,
        max_tenure_months=36,
        eligible_customer_types=["INDIVIDUAL"],
        is_active=True,
        created_by=super_admin.id,
    )
    db.add(product)
    db.commit()
    return product


# ─── Approved Loan ────────────────────────────────────────────────────────────

@pytest.fixture()
def approved_loan(db, active_customer: Customer, loan_product: LoanProduct,
                  super_admin: User) -> Loan:
    from api.security import generate_loan_number
    from api.compliance.interest_calculator import SimpleInterestCalculator
    calc = SimpleInterestCalculator()
    result = calc.calculate(
        principal=Decimal("5000"),
        annual_rate_pct=24,
        tenure_months=12,
    )
    loan = Loan(
        loan_number=generate_loan_number(),
        customer_id=active_customer.id,
        product_id=loan_product.id,
        principal_ghs=Decimal("5000"),
        annual_interest_rate=Decimal("0.24"),
        tenure_months=12,
        total_interest_ghs=result.total_interest,
        total_repayable_ghs=result.total_repayable,
        monthly_instalment_ghs=result.monthly_instalment,
        outstanding_ghs=result.total_repayable,
        status="APPROVED",
        approved_at=datetime.utcnow(),
        approved_by=super_admin.id,
        applied_by=super_admin.id,
    )
    db.add(loan)
    db.commit()
    return loan
