"""Tenant AI configuration and durable read-only investigation jobs.

Revision ID: 20260920_0095
Revises: 20260915_0094
"""
from alembic import op
import sqlalchemy as sa

revision = "20260920_0095"
down_revision = "20260915_0094"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def upgrade():
    tables = sa.inspect(op.get_bind()).get_table_names()
    # The historical baseline creates current metadata on fresh installs.
    if "ai_configuration" not in tables:
        op.create_table(
            "ai_configuration",
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), primary_key=True),
            *[sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.false())
              for name in ("enabled", "incident_enabled", "external_consent")],
            sa.Column("provider", sa.String(30), nullable=False, server_default="self_hosted"),
            sa.Column("endpoint", sa.String(500), nullable=False, server_default=""),
            sa.Column("model", sa.String(160), nullable=False, server_default=""),
            sa.Column("key_encrypted", sa.Text(), nullable=False, server_default=""),
            *[sa.Column(name, sa.Integer(), nullable=False, server_default=value) for name, value in
              (("revision", "1"), ("daily_limit", "100"), ("max_output_tokens", "1500"), ("retention_days", "7"))],
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
    if "ai_run" not in tables:
        op.create_table(
            "ai_run",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("ticket.id"), nullable=False),
            sa.Column("actor_role", sa.String(30), nullable=False),
            sa.Column("config_revision", sa.Integer(), nullable=False),
            sa.Column("request_key", sa.String(36), nullable=False),
            sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
            sa.Column("provider", sa.String(30), nullable=False),
            sa.Column("model", sa.String(160), nullable=False),
            sa.Column("prompt_version", sa.String(30), nullable=False, server_default="incident-v1"),
            sa.Column("result_text", sa.Text(), nullable=False, server_default=""),
            sa.Column("sources_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("usage_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("error_code", sa.String(80), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True)),
            sa.Column("completed_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint("tenant_id", "user_id", "request_key", name="uq_ai_run_request"),
        )
        op.create_index("ix_ai_run_tenant_id", "ai_run", ["tenant_id"])
        op.create_index("ix_ai_run_status", "ai_run", ["status"])


def downgrade():
    # Preserve evidence: rollback is allowed only before feature data exists.
    connection = op.get_bind()
    for table in ("ai_run", "ai_configuration"):
        if connection.execute(sa.text(f"SELECT 1 FROM {table} LIMIT 1")).first():
            raise RuntimeError("AI rollback requires an explicit archival plan for existing AI records.")
    op.drop_table("ai_run")
    op.drop_table("ai_configuration")
