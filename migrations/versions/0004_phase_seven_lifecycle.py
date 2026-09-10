"""phase seven lifecycle metadata"""

import sqlalchemy as sa
from alembic import op

revision = "0004_phase_seven"
down_revision = "0003_phase_six"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("lifecycle", sa.String(length=20)))
    op.add_column("findings", sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("findings", sa.Column("suppression_reason", sa.Text()))
    op.add_column("findings", sa.Column("suppression_owner", sa.String(length=200)))
    op.add_column("findings", sa.Column("suppression_expires_at", sa.String(length=40)))
    op.add_column("findings", sa.Column("enrichment_json", sa.Text(), nullable=False, server_default="[]"))


def downgrade() -> None:
    for column in (
        "enrichment_json",
        "suppression_expires_at",
        "suppression_owner",
        "suppression_reason",
        "suppressed",
        "lifecycle",
    ):
        op.drop_column("findings", column)
