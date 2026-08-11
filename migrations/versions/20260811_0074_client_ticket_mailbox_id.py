"""ClientTicket.mailbox_id: remembers which ClientMailbox a ticket
originated from (or has been replying through), so outbound replies route
via the correct mailbox instead of "whichever mailbox happens to be active
for the tenant" -- found during real GreenMail end-to-end verification of
the email channel feature.

Revision ID: 20260811_0074
Revises: 20260811_0073
"""
from alembic import op
import sqlalchemy as sa

revision = "20260811_0074"
down_revision = "20260811_0073"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("client_ticket")]
    if "mailbox_id" not in columns:
        with op.batch_alter_table("client_ticket") as batch:
            batch.add_column(sa.Column("mailbox_id", sa.Integer()))
        if bind.dialect.name != "sqlite":
            with op.batch_alter_table("client_ticket") as batch:
                batch.create_foreign_key(
                    "fk_client_ticket_mailbox_id", "client_mailbox", ["mailbox_id"], ["id"],
                )
                batch.create_index("ix_client_ticket_mailbox_id", ["mailbox_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns("client_ticket")]
    if "mailbox_id" in columns:
        fks = [
            fk["name"] for fk in inspector.get_foreign_keys("client_ticket")
            if fk.get("referred_table") == "client_mailbox" and fk["name"]
        ]
        indexes = [
            ix["name"] for ix in inspector.get_indexes("client_ticket")
            if ix["name"] and list(ix.get("column_names", ())) == ["mailbox_id"]
        ]
        with op.batch_alter_table("client_ticket") as batch:
            for ix_name in indexes:
                batch.drop_index(ix_name)
            for fk_name in fks:
                batch.drop_constraint(fk_name, type_="foreignkey")
            batch.drop_column("mailbox_id")
