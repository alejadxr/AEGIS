"""add endpoint_agents.node_token_hash

Revision ID: c4d1e7a90b21
Revises: b3aebb98b90f
Create Date: 2026-09-29 00:00:00.000000

Per-node upload credential for the endpoint agent: the SHA-256 of a random
token, NULL until issued. Base.metadata.create_all() (run at API startup) only
creates missing TABLES, so an existing database gets the column from this
migration (`alembic upgrade head`). IF NOT EXISTS keeps it safe on a database
where create_all already made the column (fresh installs).
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4d1e7a90b21"
down_revision: Union[str, None] = "b3aebb98b90f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE endpoint_agents ADD COLUMN IF NOT EXISTS node_token_hash VARCHAR(64)")


def downgrade() -> None:
    op.execute("ALTER TABLE endpoint_agents DROP COLUMN IF EXISTS node_token_hash")
