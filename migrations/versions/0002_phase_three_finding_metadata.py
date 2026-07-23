"""Phase three normalized Nuclei metadata."""

import sqlalchemy as sa
from alembic import op

revision = "0002_phase_three"
down_revision = "0001_phase_two"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("references_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("cve_ids_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("cwe_ids_json", sa.Text(), nullable=False, server_default="[]"))
    op.add_column("findings", sa.Column("cvss_score", sa.Float()))
    op.add_column("findings", sa.Column("cvss_vector", sa.Text()))


def downgrade() -> None:
    op.drop_column("findings", "cvss_vector")
    op.drop_column("findings", "cvss_score")
    op.drop_column("findings", "cwe_ids_json")
    op.drop_column("findings", "cve_ids_json")
    op.drop_column("findings", "references_json")
