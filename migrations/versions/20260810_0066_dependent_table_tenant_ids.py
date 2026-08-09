"""Add tenant_id to Comment, GroupMember, CatalogItemRouting, RequestedItem,
CatalogTask, FileAttachment, and the legacy Approval model -- defense-in-depth
against a query site that forgets to join back to the tenant-owning parent
(the same rationale ApprovalGate.tenant_id already documents). Backfilled
from each table's existing parent relationship; RequestedItem is backfilled
before CatalogTask since CatalogTask's own backfill reads it.

Revision ID: 20260810_0066
Revises: 20260807_0065
"""
from alembic import op
import sqlalchemy as sa

revision = "20260810_0066"
down_revision = "20260807_0065"
branch_labels = None
depends_on = None

# (table, backfill SQL run before the column is made NOT NULL)
_BACKFILL = [
    ("comment", "UPDATE comment SET tenant_id = "
                "(SELECT tenant_id FROM ticket WHERE ticket.id = comment.ticket_id)"),
    ("approval", "UPDATE approval SET tenant_id = "
                 "(SELECT tenant_id FROM enterprise_record WHERE enterprise_record.id = approval.enterprise_record_id)"),
    ("catalog_item_routing", "UPDATE catalog_item_routing SET tenant_id = "
                             "(SELECT tenant_id FROM catalog_item WHERE catalog_item.id = catalog_item_routing.catalog_item_id)"),
    ("group_member", "UPDATE group_member SET tenant_id = "
                     "(SELECT tenant_id FROM support_group WHERE support_group.id = group_member.group_id)"),
    ("requested_item", "UPDATE requested_item SET tenant_id = "
                       "(SELECT tenant_id FROM catalog_request WHERE catalog_request.id = requested_item.request_id)"),
    ("catalog_task", "UPDATE catalog_task SET tenant_id = "
                     "(SELECT tenant_id FROM requested_item WHERE requested_item.id = catalog_task.requested_item_id)"),
]

_TABLES = ["comment", "approval", "catalog_item_routing", "group_member", "requested_item", "catalog_task", "file_attachment"]


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    added = set()
    for table in _TABLES:
        columns = [c["name"] for c in inspector.get_columns(table)]
        if "tenant_id" not in columns:
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column("tenant_id", sa.Integer()))
            added.add(table)

    for table, sql in _BACKFILL:
        op.execute(sql)
    # file_attachment has three mutually-exclusive parents (see its model
    # docstring); ticket/enterprise_record cover every row (comment_id, when
    # set, is always paired with a ticket_id too).
    op.execute(
        "UPDATE file_attachment SET tenant_id = "
        "(SELECT tenant_id FROM ticket WHERE ticket.id = file_attachment.ticket_id) "
        "WHERE ticket_id IS NOT NULL"
    )
    op.execute(
        "UPDATE file_attachment SET tenant_id = "
        "(SELECT tenant_id FROM enterprise_record WHERE enterprise_record.id = file_attachment.enterprise_record_id) "
        "WHERE enterprise_record_id IS NOT NULL AND tenant_id IS NULL"
    )

    for table in added:
        # Not-null is safe now that every row was just backfilled above.
        with op.batch_alter_table(table) as batch:
            batch.alter_column("tenant_id", nullable=False)
        if bind.dialect.name != "sqlite":
            with op.batch_alter_table(table) as batch:
                batch.create_foreign_key(f"fk_{table}_tenant_id", "tenant", ["tenant_id"], ["id"])
                batch.create_index(f"ix_{table}_tenant_id", ["tenant_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in _TABLES:
        columns = [c["name"] for c in inspector.get_columns(table)]
        if "tenant_id" not in columns:
            continue
        fks = [
            fk["name"] for fk in inspector.get_foreign_keys(table)
            if fk.get("referred_table") == "tenant" and fk["name"]
        ]
        indexes = [
            ix["name"] for ix in inspector.get_indexes(table)
            if ix["name"] and list(ix.get("column_names", ())) == ["tenant_id"]
        ]
        with op.batch_alter_table(table) as batch:
            for ix_name in indexes:
                batch.drop_index(ix_name)
            for fk_name in fks:
                batch.drop_constraint(fk_name, type_="foreignkey")
            batch.drop_column("tenant_id")
