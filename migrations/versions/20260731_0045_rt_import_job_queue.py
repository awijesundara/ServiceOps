"""Move RT import off the synchronous web request path: RT import could
take many minutes against a real (often slow) RT instance, and running it
inline routinely exceeded gunicorn's worker timeout -- which kills the
entire worker process (and every other in-flight request on it), not just
that one request. RTImportJob queues the run; the background worker
(process_rt_import_jobs, tools/outbox_worker.py) does the actual work.

Revision ID: 20260731_0045
Revises: 20260731_0044
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0045"
down_revision = "20260731_0044"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "rt_import_job" in inspector.get_table_names():
        return
    op.create_table(
        "rt_import_job",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("search_query", sa.String(length=500), nullable=False),
        sa.Column("record_limit", sa.Integer(), nullable=True),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="Pending"),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_rt_import_job_tenant_id", "rt_import_job", ["tenant_id"])
    op.create_index("ix_rt_import_job_status", "rt_import_job", ["status"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "rt_import_job" in inspector.get_table_names():
        op.drop_table("rt_import_job")
