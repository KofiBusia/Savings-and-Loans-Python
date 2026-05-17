"""Initial schema — all tables

Revision ID: 0001
Revises:
Create Date: 2025-01-01 00:00:00.000000

This migration is auto-generated from models.py.
Re-generate with: alembic revision --autogenerate -m "description"
"""
from __future__ import annotations
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tables are created via Base.metadata.create_all() in database.py init_db().
    # This migration serves as the baseline for future incremental migrations.
    # To generate the full SQL: alembic upgrade head --sql
    pass


def downgrade() -> None:
    pass
