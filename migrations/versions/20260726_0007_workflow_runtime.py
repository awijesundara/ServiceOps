"""Add versioned declarative workflow runtime.

Revision ID: 20260726_0007
Revises: 20260726_0006
"""
from alembic import op
import sqlalchemy as sa

revision = "20260726_0007"
down_revision = "20260726_0006"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "workflow_definition" not in tables:
        op.create_table(
            "workflow_definition",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("workflow_key", sa.String(120), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("event_type", sa.String(80), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("published_version_id", sa.Integer()),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("tenant_id", "workflow_key", name="uq_workflow_definition_key"),
        )
        op.create_index("ix_workflow_definition_tenant_id", "workflow_definition", ["tenant_id"])
    if "workflow_version" not in tables:
        op.create_table(
            "workflow_version",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("definition_id", sa.Integer(), sa.ForeignKey("workflow_definition.id"), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("definition_json", sa.Text(), nullable=False),
            sa.Column("package_hash", sa.String(64), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("published_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("definition_id", "version", name="uq_workflow_definition_version"),
        )
        op.create_index("ix_workflow_version_tenant_id", "workflow_version", ["tenant_id"])
    if "workflow_job" not in tables:
        op.create_table(
            "workflow_job",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("event_id", sa.String(36), nullable=False, unique=True),
            sa.Column("event_type", sa.String(80), nullable=False),
            sa.Column("target_type", sa.String(30), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=False),
            sa.Column("context_json", sa.Text(), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_error", sa.Text()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        )
        op.create_index("ix_workflow_job_state", "workflow_job", ["state"])
        op.create_index("ix_workflow_job_tenant_id", "workflow_job", ["tenant_id"])
    if "workflow_execution" not in tables:
        op.create_table(
            "workflow_execution",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("job_id", sa.Integer(), sa.ForeignKey("workflow_job.id"), nullable=False),
            sa.Column("version_id", sa.Integer(), sa.ForeignKey("workflow_version.id"), nullable=False),
            sa.Column("correlation_id", sa.String(36), nullable=False),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("input_json", sa.Text(), nullable=False),
            sa.Column("output_json", sa.Text(), nullable=False),
            sa.Column("error", sa.Text()),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.UniqueConstraint("job_id", "version_id", name="uq_workflow_job_version"),
        )
        op.create_index("ix_workflow_execution_tenant_id", "workflow_execution", ["tenant_id"])


def downgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for name in ("workflow_execution", "workflow_job", "workflow_version", "workflow_definition"):
        if name in tables:
            op.drop_table(name)
