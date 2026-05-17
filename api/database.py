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


engine = create_engine(
    settings.database_url,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_pre_ping=True,         # detect stale connections
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
    log.info("database tables verified/created")


def get_db():
    """FastAPI dependency — yields a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
