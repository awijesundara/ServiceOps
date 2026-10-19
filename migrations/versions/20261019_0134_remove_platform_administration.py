"""Remove Platform administration: sandboxes, release tracks, IP allowlist and insights.

Drops the project_sandbox table and the stored install policy (release track
and IP allowlist). Application versions up to 1.113.56 read the table only on
the sandbox administration page, so they keep working while this runs.

Revision ID: 20261019_0134
Revises: 20261018_0133
"""
from alembic import op
import sqlalchemy as sa

revision = "20261019_0134"
down_revision = "20261018_0133"
branch_labels = None
depends_on = None
serviceops_migration_phase = "contract"
serviceops_contract_after_version = "1.113.56"


def upgrade():
    bind = op.get_bind()
    if "project_sandbox" in sa.inspect(bind).get_table_names():
        op.drop_table("project_sandbox")
    bind.execute(sa.text("DELETE FROM platform_setting WHERE key = 'PREMIUM_PLATFORM_POLICY'"))


def downgrade():
    # The table comes back empty; sandboxes held synthetic data only.
    op.create_table(
        "project_sandbox",
        sa.Column("slot", sa.Integer(), nullable=False),
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True),
        sa.Column("owner_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("image", sa.String(255)),
        sa.Column("last_error", sa.String(160), nullable=False),
        sa.Column("events_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state IN ('queued','provisioning','ready','failed','deleting','deleted')",
                           name="ck_project_sandbox_state"),
        sa.CheckConstraint("slot IN (1,2)", name="ck_project_sandbox_slot"),
    )
