"""widen actions.status to VARCHAR(32)

Revision ID: d5f2a8c13e47
Revises: c4d1e7a90b21
Create Date: 2026-10-03 00:00:00.000000

"skipped_not_applicable" is 22 characters; actions.status was VARCHAR(20), so
inserting it raised StringDataRightTruncationError and rolled back the whole
incident path. Longest status written anywhere is 22; 32 leaves headroom.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "d5f2a8c13e47"
down_revision: Union[str, None] = "c4d1e7a90b21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE actions ALTER COLUMN status TYPE VARCHAR(32)")


def downgrade() -> None:
    op.execute("ALTER TABLE actions ALTER COLUMN status TYPE VARCHAR(20)")
