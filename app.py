"""
Ghana Savings & Loans — Production-Ready FastAPI Backend
=========================================================
Entry points:
  Development : python app.py
  Production  : uvicorn app:app --workers 4 --host 0.0.0.0 --port 8000

API Docs (dev only): http://localhost:8000/api/docs
Health:              http://localhost:8000/api/v1/health

Regulatory foundation:
  - AML Act 2020 (Act 1044)
  - Data Protection Act 2012 (Act 843)
  - Cybersecurity Act 2020 (Act 1038)
  - Digital Credit Directive 2025
  - Borrowers & Lenders Act 2020
  - Credit Reporting Regulations 2020 (L.I. 2394)
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from api.config import settings
from api.database import init_db
from api.middleware.data_residency import DataResidencyMiddleware
from api.routers import admin, auth, compliance, customers, health, loans, savings

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger(__name__)


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(
        "startup env=%s version=%s institution=%s",
        settings.node_env, settings.app_version, settings.institution_name,
    )
    init_db()
    _seed_admin()
    yield
    log.info("shutdown — all connections closed")


def _seed_admin() -> None:
    from api.database import SessionLocal
    from api import models
    from api.security import hash_password

    db = SessionLocal()
    try:
        existing = db.query(models.User).filter_by(email=settings.admin_email).first()
        if not existing:
            db.add(models.User(
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                roles=["SUPER_ADMIN", "COMPLIANCE_OFFICER", "CREDIT_MANAGER"],
                mfa_enabled=False,
                is_active=True,
            ))
            db.commit()
            log.info("default admin created: %s", settings.admin_email)
        else:
            log.info("admin user already exists: %s", settings.admin_email)
    finally:
        db.close()


# ─── App Factory ──────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Ghana Savings & Loans API",
        description=(
            "BoG-licensed savings & loan platform. "
            "Simple interest only (DCD 2025, Clause 14). "
            "AML Act 1044 · Data Protection Act 843 · Cybersecurity Act 1038."
        ),
        version=settings.app_version,
        lifespan=lifespan,
        # Swagger/ReDoc disabled in production — BoG security requirement
        docs_url="/api/docs" if settings.node_env != "production" else None,
        redoc_url="/api/redoc" if settings.node_env != "production" else None,
        openapi_url="/api/openapi.json" if settings.node_env != "production" else None,
    )

    # ── Middleware (outermost → innermost) ─────────────────────────────────
    app.add_middleware(GZipMiddleware, minimum_size=512)

    # Data residency: blocks PII going to non-Ghana IPs (Act 843, s.25)
    app.add_middleware(DataResidencyMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Content-Type", "Authorization",
            "X-MFA-Token", "X-Device-Id", "X-Request-Id", "X-Idempotency-Key",
        ],
        expose_headers=["X-Request-Id", "X-RateLimit-Remaining"],
        max_age=600,
    )

    # ── Request ID tracking ───────────────────────────────────────────────
    @app.middleware("http")
    async def inject_request_id(request: Request, call_next: Any) -> Response:
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response

    # ── Global exception handler ──────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", "unknown")
        log.exception("unhandled_error request_id=%s path=%s", rid, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": rid},
        )

    # ── Routers ───────────────────────────────────────────────────────────
    PREFIX = "/api/v1"
    for router in [
        health.router,
        auth.router,
        customers.router,
        loans.router,
        savings.router,
        compliance.router,
        admin.router,
    ]:
        app.include_router(router, prefix=PREFIX)

    return app


app = create_app()


# ─── Main Entry Point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 62)
    print(f"  Ghana Savings & Loans API  v{settings.app_version}")
    print(f"  Institution : {settings.institution_name}")
    print(f"  BoG Licence : {settings.bog_licence_number}")
    print(f"  Environment : {settings.node_env}")
    print(f"  Port        : {settings.app_port}")
    print(f"  API         : http://localhost:{settings.app_port}/api/v1")
    print(f"  Swagger     : http://localhost:{settings.app_port}/api/docs")
    print("=" * 62)

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=settings.app_port,
        workers=settings.uvicorn_workers if settings.node_env == "production" else 1,
        reload=settings.node_env == "development",
        log_level="info",
        access_log=True,
        server_header=False,   # Don't expose server version
        date_header=True,
    )
