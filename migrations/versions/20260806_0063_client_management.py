"""Add tenant-scoped external client support workspace.

Revision ID: 20260806_0063
Revises: 20260806_0062
"""
from alembic import op
import sqlalchemy as sa


revision = "20260806_0063"
down_revision = "20260806_0062"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # 20260726_0001 (the baseline migration) creates every table present in
    # the current ORM metadata on a fresh database -- including these four,
    # since they're already defined in serviceops_models.py by the time that
    # migration runs. On a fresh DB these tables already exist by the time
    # this migration executes; on a DB adopted before this change existed,
    # they don't. Guard every create_table the same way every other
    # post-baseline migration that adds a new table already does (e.g.
    # 20260806_0060, 20260805_0058/0059).
    if not inspector.has_table("client_organization"):
        op.create_table(
            "client_organization",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(180), nullable=False),
            sa.Column("domain", sa.String(180), nullable=False, server_default=""),
            sa.Column("external_id", sa.String(120)),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_client_organization_tenant_name"),
        )
        op.create_index("ix_client_organization_tenant_id", "client_organization", ["tenant_id"])
    if not inspector.has_table("client_contact"):
        op.create_table(
            "client_contact",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("client_organization.id"), nullable=False),
            sa.Column("name", sa.String(160), nullable=False),
            sa.Column("email", sa.String(254), nullable=False),
            sa.Column("phone", sa.String(60), nullable=False, server_default=""),
            sa.Column("job_title", sa.String(120), nullable=False, server_default=""),
            sa.Column("preferred_language", sa.String(30), nullable=False, server_default="English"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "email", name="uq_client_contact_tenant_email"),
        )
        op.create_index("ix_client_contact_tenant_id", "client_contact", ["tenant_id"])
        op.create_index("ix_client_contact_organization_id", "client_contact", ["organization_id"])
    if not inspector.has_table("client_ticket"):
        op.create_table(
            "client_ticket",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("number", sa.String(24), nullable=False),
            sa.Column("subject", sa.String(200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("status", sa.String(30), nullable=False, server_default="New"),
            sa.Column("priority", sa.String(20), nullable=False, server_default="Normal"),
            sa.Column("ticket_type", sa.String(30), nullable=False, server_default="Question"),
            sa.Column("channel", sa.String(30), nullable=False, server_default="Web"),
            sa.Column("tags", sa.String(500), nullable=False, server_default=""),
            sa.Column("contact_id", sa.Integer(), sa.ForeignKey("client_contact.id"), nullable=False),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("client_organization.id"), nullable=False),
            sa.Column("assignee_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("support_group_id", sa.Integer(), sa.ForeignKey("support_group.id"), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("solved_at", sa.DateTime(timezone=True)),
            sa.UniqueConstraint("number", name="uq_client_ticket_number"),
        )
        for column in ("tenant_id", "number", "status", "priority", "contact_id", "organization_id", "assignee_id", "support_group_id"):
            op.create_index(f"ix_client_ticket_{column}", "client_ticket", [column])
    if not inspector.has_table("client_ticket_message"):
        op.create_table(
            "client_ticket_message",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("client_ticket_id", sa.Integer(), sa.ForeignKey("client_ticket.id"), nullable=False),
            sa.Column("author_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("visibility", sa.String(20), nullable=False, server_default="public"),
            sa.Column("event_type", sa.String(30), nullable=False, server_default="reply"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_client_ticket_message_tenant_id", "client_ticket_message", ["tenant_id"])
        op.create_index("ix_client_ticket_message_client_ticket_id", "client_ticket_message", ["client_ticket_id"])

    # Every existing tenant receives the governed access team. Always run,
    # even when the tables above already existed (fresh-DB path via the
    # baseline migration): idempotent via NOT EXISTS, and it's the only
    # place that backfills SysOps for tenants that predate this feature.
    # Membership is intentionally not inferred; administrators assign
    # SysOps members explicitly.
    op.execute(sa.text("""
        INSERT INTO support_group (name, group_type, active, tenant_id)
        SELECT 'SysOps', 'Client Support', true, tenant.id
        FROM tenant
        WHERE NOT EXISTS (
            SELECT 1 FROM support_group
            WHERE support_group.tenant_id = tenant.id AND lower(support_group.name) = 'sysops'
        )
    """))


def downgrade():
    op.drop_table("client_ticket_message")
    op.drop_table("client_ticket")
    op.drop_table("client_contact")
    op.drop_table("client_organization")
    op.execute(sa.text("""
        DELETE FROM support_group
        WHERE lower(name) = 'sysops' AND group_type = 'Client Support'
          AND NOT EXISTS (SELECT 1 FROM group_member WHERE group_member.group_id = support_group.id)
    """))
