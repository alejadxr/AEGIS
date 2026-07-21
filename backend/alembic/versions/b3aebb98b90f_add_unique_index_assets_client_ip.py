"""add partial unique index on assets(client_id, ip_address)

Revision ID: b3aebb98b90f
Revises: a253b97201e8
Create Date: 2026-07-21 00:00:00.000000

Makes asset identity actually unique at the DB level. Multiple write paths
(app/main.py `_auto_discover_localhost`, app/api/setup.py `POST /register`,
app/api/nodes.py `POST /report-assets` — and anything written later) each
do their own "find existing asset, else create" lookup. When that lookup
fails to match an existing row for reasons outside the DB's control (e.g.
a mutated in-memory list during a scan loop), a duplicate `assets` row is
silently forked instead of the existing one being updated, and destructive
field overwrites (ports, technologies, risk_score) can occur on whichever
row *does* get matched.

This constraint does not fix the upsert logic itself (see the accompanying
fix to the write paths above) — it makes it structurally impossible for
any current or future code path to reintroduce silent duplicate rows: a
violated constraint fails loudly (IntegrityError) instead of quietly
forking state.

IMPORTANT — SEQUENCING: this migration MUST run AFTER the one-off repair
that collapses existing duplicate (client_id, ip_address) groups in the
`assets` table down to one row each. As of the time this migration was
written, production has 17 duplicate hostname groups sharing an IP with
another row (e.g. eppc-3031 x11, unknown-7000 x6). If those duplicates
still exist when this migration runs, `CREATE UNIQUE INDEX` will fail
outright with a "could not create unique index" error. Do not stamp/run
this migration until that repair's operator confirms 0 duplicate
(client_id, ip_address) groups remain, e.g.:

    SELECT client_id, ip_address, COUNT(*)
    FROM assets
    WHERE ip_address IS NOT NULL AND ip_address <> ''
    GROUP BY client_id, ip_address
    HAVING COUNT(*) > 1;

    -- must return 0 rows before `alembic upgrade head` is run.

NULL/empty ip_address rows are excluded from the constraint (partial
index), so hostname-only assets discovered without an IP yet are
unaffected and can coexist without tripping this index.
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
        "uq_assets_client_ip",
        "assets",
        ["client_id", "ip_address"],
        unique=True,
        postgresql_where=sa.text("ip_address IS NOT NULL AND ip_address <> ''"),
    )


def downgrade() -> None:
    op.drop_index("uq_assets_client_ip", table_name="assets")
