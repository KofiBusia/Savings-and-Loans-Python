"""
Application Configuration
All settings are loaded from environment variables (see .env.example).
Pydantic-settings validates all values at startup — missing required vars crash immediately.
"""
from __future__ import annotations

import os
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────────────────────
    node_env: str = "development"
    app_version: str = "1.0.0"
    app_port: int = 8000
    uvicorn_workers: int = 4

    # ── Institution ───────────────────────────────────────────────────────────
    institution_name: str = "Crestline Savings and Loans Ltd"
    bog_licence_number: str = "MFI-XXXX/YYYY"
    ghana_data_region: str = "gh-accra-1"

    # ── Security ──────────────────────────────────────────────────────────────
    secret_key: str                              # REQUIRED
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    mfa_totp_issuer: str = "Crestline S&L"

    # ── Admin Seed ────────────────────────────────────────────────────────────
    admin_email: str = "admin@gsl.com.gh"
    admin_password: str = "Admin@1234!"          # Change in production

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "postgresql+psycopg2://gsl:gsl_dev@localhost:5432/gsl_db"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout: int = 30

    # ── CORS ──────────────────────────────────────────────────────────────────
    allowed_origins: List[str] = [
        "http://localhost:3000",   # Front-office (dev)
        "http://localhost:3002",   # Back-office (dev)
        "https://portal.savingsloans.com.gh",
        "https://admin.savingsloans.com.gh",
    ]

    # ── GhIPSS Mobile Money ───────────────────────────────────────────────────
    ghipss_api_key: str = "GHIPSS_SANDBOX_KEY"
    ghipss_api_secret: str = "GHIPSS_SANDBOX_SECRET"
    ghipss_institution_code: str = "MFI001"
    mock_ghipss: bool = True                     # Set False in production

    # ── Credit Bureaus ────────────────────────────────────────────────────────
    xds_api_key: str = "XDS_SANDBOX_KEY"
    xds_api_url: str = "https://sandbox.xds.com.gh/api/v2"
    db_ghana_api_key: str = "DB_GHANA_SANDBOX_KEY"
    db_ghana_api_url: str = "https://sandbox.dbghana.com/api/v1"
    my_credit_api_key: str = "MYCREDIT_SANDBOX_KEY"
    my_credit_api_url: str = "https://sandbox.mycreditscore.com.gh/api/v1"
    mock_credit_bureaus: bool = True

    # ── Ghana Card API (NIA) ──────────────────────────────────────────────────
    ghana_card_api_url: str = "https://sandbox.nia.gov.gh/api/v1"
    ghana_card_api_key: str = "NIA_SANDBOX_KEY"
    mock_ghana_card_api: bool = True

    # ── Payment Gateways ──────────────────────────────────────────────────────
    paystack_secret_key: str = "sk_test_PAYSTACK_KEY"
    paystack_public_key: str = "pk_test_PAYSTACK_PUBLIC_KEY"
    flutterwave_secret_key: str = "FLUTTERWAVE_TEST_KEY"
    express_pay_merchant_id: str = "EXPRESS_PAY_MERCHANT"
    express_pay_api_key: str = "EXPRESS_PAY_KEY"
    hubtel_client_id: str = "HUBTEL_CLIENT_ID"
    hubtel_client_secret: str = "HUBTEL_CLIENT_SECRET"
    default_payment_gateway: str = "PAYSTACK"

    # ── SMS/USSD (mNotify / Hubtel) ───────────────────────────────────────────
    mnotify_api_key: str = "MNOTIFY_KEY"
    mnotify_sender_id: str = "CSL"
    hubtel_sms_client_id: str = "HUBTEL_SMS_ID"
    hubtel_sms_client_secret: str = "HUBTEL_SMS_SECRET"

    # ── FIC Reporting ─────────────────────────────────────────────────────────
    fic_submission_url: str = "https://sandbox.fic.gov.gh/api/v1"
    fic_api_key: str = "FIC_SANDBOX_KEY"
    fic_reporting_officer: str = "compliance@gsl.com.gh"

    # ── Redis (task queue / session cache) ───────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Sentry (error tracking) ───────────────────────────────────────────────
    sentry_dsn: str = ""

    # ── Compliance Parameters ─────────────────────────────────────────────────
    ctr_threshold_ghs: float = 10000.00          # AML Act 1044 — do not change without BoG approval
    complaint_resolution_sla_days: int = 20      # DCD 2025
    cdd_review_low_risk_years: int = 3
    cdd_review_medium_risk_years: int = 2
    cdd_review_high_risk_years: int = 1

    @field_validator("node_env")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"development", "staging", "production", "test"}
        if v not in allowed:
            raise ValueError(f"node_env must be one of {allowed}")
        return v

    @field_validator("bog_licence_number")
    @classmethod
    def validate_bog_licence(cls, v: str) -> str:
        import re
        if v.startswith("MFI-XXXX"):
            return v   # placeholder — ok for development
        if not re.match(r"^(ARN|MFI|SDI|PSP|EMI)-\d{3,6}/\d{4}$", v):
            raise ValueError(f"Invalid BoG licence format: {v}")
        return v


settings = Settings()
