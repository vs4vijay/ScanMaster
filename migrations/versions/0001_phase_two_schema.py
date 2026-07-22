"""Phase two run, finding, and artifact schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001_phase_two"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scanner", sa.String(40), nullable=False),
        sa.Column("target_kind", sa.String(20), nullable=False),
        sa.Column("target_value", sa.Text(), nullable=False),
        sa.Column("target_canonical", sa.Text(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.Column("external_id", sa.String(200)),
        sa.Column("error", sa.Text()),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("native_id", sa.String(200), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("remediation", sa.Text()),
        sa.Column("location", sa.Text()),
        sa.Column("evidence", sa.Text()),
    )
    op.create_index("ix_findings_run_id", "findings", ["run_id"])
    op.create_table(
        "scanner_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner", sa.String(40), nullable=False),
        sa.Column("external_id", sa.String(200), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
    )
    op.create_index("ix_scanner_jobs_run_id", "scanner_jobs", ["run_id"])
    op.create_table(
        "occurrences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("location", sa.Text()),
        sa.Column("evidence", sa.Text()),
    )
    op.create_index("ix_occurrences_finding_id", "occurrences", ["finding_id"])
    op.create_table(
        "artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_index("ix_artifacts_run_id", "artifacts", ["run_id"])


def downgrade() -> None:
    op.drop_table("artifacts")
    op.drop_table("occurrences")
    op.drop_table("scanner_jobs")
    op.drop_table("findings")
    op.drop_table("runs")
