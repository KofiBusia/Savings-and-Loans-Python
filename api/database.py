"""
Database engine, session factory, and base model.
Uses synchronous SQLAlchemy (psycopg2) — fits the sync dependency injection pattern.
For async routes, use run_in_executor or switch engine to asyncpg.
"""
from __future__ import annotations

import logging

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from api.config import settings

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_is_sqlite = settings.database_url.startswith("sqlite")
engine = create_engine(
    settings.database_url,
    **({} if _is_sqlite else {
        "pool_size": settings.db_pool_size,
        "max_overflow": settings.db_max_overflow,
        "pool_timeout": settings.db_pool_timeout,
    }),
    pool_pre_ping=not _is_sqlite,
    echo=settings.node_env == "development",
)

# Enforce UTC timestamps at the connection level (PostgreSQL only)
if settings.database_url.startswith("postgresql"):
    @event.listens_for(engine, "connect")
    def set_utc_timezone(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.close()


SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


def init_db() -> None:
    """Create all tables if they don't exist (idempotent)."""
    import api.models  # noqa: F401 — ensure models are registered on Base
    Base.metadata.create_all(bind=engine)
    _migrate_columns()
    log.info("database tables verified/created")


def _migrate_columns() -> None:
    """Add new columns to existing tables without dropping data (SQLite-safe)."""
    _migrations = [
        ("customers", "savings_product_id", "VARCHAR(36)"),
        ("loan_products", "savings_ratio", "NUMERIC(5,4) DEFAULT 0.7000"),
        ("loan_products", "collateral_ratio", "NUMERIC(5,4) DEFAULT 0.5000"),
        ("customers", "assigned_officer_id", "VARCHAR(36)"),
        ("savings_transactions", "paystack_reference", "VARCHAR(100)"),
        ("savings_transactions", "status", "VARCHAR(20) DEFAULT 'CONFIRMED'"),
    ]
    with engine.connect() as conn:
        for table, col, col_type in _migrations:
            try:
                result = conn.execute(text(f"SELECT {col} FROM {table} LIMIT 1"))
                result.close()
            except Exception:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
                conn.commit()
                log.info("migrated: added %s.%s", table, col)


def get_db():
    """FastAPI dependency — yields a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
