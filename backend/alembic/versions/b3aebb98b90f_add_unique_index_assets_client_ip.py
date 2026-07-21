"""add partial unique index on assets(client_id, ip_address, hostname)

Revision ID: b3aebb98b90f
Revises: a253b97201e8
Create Date: 2026-07-21 00:00:00.000000

Makes asset identity actually unique at the DB level. hostname is part of
the key because multiple genuinely distinct services share 127.0.0.1 (e.g.
python-8099, eppc-3031, unknown-7000) -- each gets its own Asset row by
design. A (client_id, ip_address)-only constraint would reject these
legitimate multi-service localhost rows.

NULL/empty ip_address rows are excluded from the constraint (partial
index), so hostname-only assets (no IP discovered yet) aren't constrained.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b3aebb98b90f"
down_revision: Union[str, None] = "a253b97201e8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "uq_assets_client_ip_host",
        "assets",
        ["client_id", "ip_address", "hostname"],
        unique=True,
        postgresql_where=sa.text("ip_address IS NOT NULL AND ip_address <> ''"),
    )


def downgrade() -> None:
    op.drop_index("uq_assets_client_ip_host", table_name="assets")
