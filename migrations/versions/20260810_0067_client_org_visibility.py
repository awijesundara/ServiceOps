"""Add ClientOrganization.restricted_visibility and the
client_organization_access grant table (Client Management phase 1:
per-organization visibility).

Revision ID: 20260810_0067
Revises: 20260810_0066
"""
from alembic import op
import sqlalchemy as sa

revision = "20260810_0067"
down_revision = "20260810_0066"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    columns = [c["name"] for c in inspector.get_columns("client_organization")]
    if "restricted_visibility" not in columns:
        with op.batch_alter_table("client_organization") as batch:
            batch.add_column(sa.Column(
                "restricted_visibility", sa.Boolean(), nullable=False, server_default=sa.false(),
            ))

    if not inspector.has_table("client_organization_access"):
        op.create_table(
            "client_organization_access",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("client_organization.id"), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("group_id", sa.Integer(), sa.ForeignKey("support_group.id")),
            sa.Column("updated_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint(
                "organization_id", "user_id", "group_id", name="uq_client_org_access_org_user_group",
            ),
            sa.CheckConstraint(
                "(user_id IS NOT NULL AND group_id IS NULL) OR (user_id IS NULL AND group_id IS NOT NULL)",
                name="ck_client_org_access_exactly_one_grantee",
            ),
        )
        op.create_index(
            "ix_client_organization_access_tenant_id", "client_organization_access", ["tenant_id"],
        )
        op.create_index(
            "ix_client_organization_access_organization_id", "client_organization_access", ["organization_id"],
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("client_organization_access"):
        op.drop_table("client_organization_access")
    columns = [c["name"] for c in inspector.get_columns("client_organization")]
    if "restricted_visibility" in columns:
        with op.batch_alter_table("client_organization") as batch:
            batch.drop_column("restricted_visibility")
