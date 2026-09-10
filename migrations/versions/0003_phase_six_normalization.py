"""phase six normalization metadata

Revision ID: 0003_phase_six
Revises: 0002_phase_three
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_phase_six"
down_revision = "0002_phase_three"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("sources_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("confidence", sa.String(length=40), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "sources_json")
