"""Initial schema — baseline of all existing tables.

Revision ID: 001_initial
Revises: None
Create Date: 2026-03-19

This is a baseline migration. It represents the schema as it exists at the
time Alembic was introduced. If you are starting from a fresh database,
running this migration will create all tables. If you already have the tables,
stamp the database instead:

    alembic stamp 001_initial
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # This is a baseline migration.
    # All tables are created by SQLAlchemy's Base.metadata.create_all() on first boot.
    # To adopt Alembic on an existing database, run:
    #   alembic stamp 001_initial
    # For fresh databases, the tables will be created by create_all and then stamped.
    pass


def downgrade() -> None:
    # Dropping all tables is intentionally not automated.
    # Use: DROP SCHEMA public CASCADE; CREATE SCHEMA public;
    pass
