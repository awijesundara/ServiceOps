"""Client Management email channel: ClientMailbox (IMAP/SMTP config),
ClientTicketMessage.message_id/in_reply_to (threading), ClientTicketMessage.author_id
made nullable (inbound-email messages have no internal User author),
FileAttachment.client_ticket_id (email attachments).

Revision ID: 20260811_0073
Revises: 20260811_0072
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0073"
down_revision = "20260811_0072"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table("client_mailbox"):
        op.create_table(
            "client_mailbox",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(120), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("imap_host", sa.String(255), nullable=False, server_default=""),
            sa.Column("imap_port", sa.Integer(), nullable=False, server_default="993"),
            sa.Column("imap_use_ssl", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("imap_username", sa.String(255), nullable=False, server_default=""),
            sa.Column("imap_password_encrypted", sa.Text()),
            sa.Column("imap_folder", sa.String(120), nullable=False, server_default="INBOX"),
            sa.Column("smtp_host", sa.String(255), nullable=False, server_default=""),
            sa.Column("smtp_port", sa.Integer(), nullable=False, server_default="587"),
            sa.Column("smtp_use_tls", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("smtp_username", sa.String(255), nullable=False, server_default=""),
            sa.Column("smtp_password_encrypted", sa.Text()),
            sa.Column("from_address", sa.String(254), nullable=False, server_default=""),
            sa.Column("from_name", sa.String(160), nullable=False, server_default=""),
            sa.Column("default_organization_id", sa.Integer(), sa.ForeignKey("client_organization.id")),
            sa.Column("auto_create_organization_by_domain", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_polled_at", sa.DateTime(timezone=True)),
            sa.Column("last_poll_status", sa.String(20), nullable=False, server_default="never_run"),
            sa.Column("last_poll_error", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("tenant_id", "name", name="uq_client_mailbox_tenant_name"),
        )
        op.create_index("ix_client_mailbox_tenant_id", "client_mailbox", ["tenant_id"])

    message_columns = [c["name"] for c in inspector.get_columns("client_ticket_message")]
    with op.batch_alter_table("client_ticket_message") as batch:
        if "message_id" not in message_columns:
            batch.add_column(sa.Column("message_id", sa.String(255)))
        if "in_reply_to" not in message_columns:
            batch.add_column(sa.Column("in_reply_to", sa.String(255)))
        batch.alter_column("author_id", nullable=True)
    if "message_id" not in message_columns and bind.dialect.name != "sqlite":
        with op.batch_alter_table("client_ticket_message") as batch:
            batch.create_index("ix_client_ticket_message_message_id", ["message_id"])

    attachment_columns = [c["name"] for c in inspector.get_columns("file_attachment")]
    if "client_ticket_id" not in attachment_columns:
        with op.batch_alter_table("file_attachment") as batch:
            batch.add_column(sa.Column("client_ticket_id", sa.Integer()))
        if bind.dialect.name != "sqlite":
            with op.batch_alter_table("file_attachment") as batch:
                batch.create_foreign_key(
                    "fk_file_attachment_client_ticket_id", "client_ticket", ["client_ticket_id"], ["id"],
                )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    attachment_columns = [c["name"] for c in inspector.get_columns("file_attachment")]
    if "client_ticket_id" in attachment_columns:
        fks = [
            fk["name"] for fk in inspector.get_foreign_keys("file_attachment")
            if fk.get("referred_table") == "client_ticket" and fk["name"]
        ]
        with op.batch_alter_table("file_attachment") as batch:
            for fk_name in fks:
                batch.drop_constraint(fk_name, type_="foreignkey")
            batch.drop_column("client_ticket_id")

    message_columns = [c["name"] for c in inspector.get_columns("client_ticket_message")]
    message_indexes = [
        ix["name"] for ix in inspector.get_indexes("client_ticket_message")
        if ix["name"] and list(ix.get("column_names", ())) == ["message_id"]
    ]
    with op.batch_alter_table("client_ticket_message") as batch:
        for ix_name in message_indexes:
            batch.drop_index(ix_name)
        if "message_id" in message_columns:
            batch.drop_column("message_id")
        if "in_reply_to" in message_columns:
            batch.drop_column("in_reply_to")
        batch.alter_column("author_id", nullable=False)

    if inspector.has_table("client_mailbox"):
        op.drop_table("client_mailbox")
