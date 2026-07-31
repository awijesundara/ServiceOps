"""Register "DBA Team" (not just "DBA") as an alias of "Database" -- staff
also use that longer form. Seeds the alias for every tenant that has a
Database team, then runs the same merge used by 20260731_0033 so any
pre-existing "DBA Team" SupportGroup (which predates this alias) is folded
into Database instead of being left as an orphaned duplicate.

Revision ID: 20260731_0037
Revises: 20260731_0036
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0037"
down_revision = "20260731_0036"
branch_labels = None
depends_on = None

FK_TARGETS = (
    ("configuration_item", "support_group_id"),
    ("change_ownership", "group_id"),
    ("ticket_assignment_group", "group_id"),
    ("catalog_item_routing", "support_group_id"),
    ("directory_group_mapping", "support_group_id"),
    ("directory_managed_membership", "group_id"),
    ("service_offering", "support_group_id"),
    ("catalog_task", "assignment_group_id"),
    ("operational_task", "assignment_group_id"),
    ("monitoring_source", "assignment_group_id"),
)


def _merge(bind, fk_targets, dup_id, target_id):
    params = {"dup": dup_id, "target": target_id}
    for table, column in fk_targets:
        bind.execute(
            sa.text(f"UPDATE {table} SET {column} = :target WHERE {column} = :dup"),
            params,
        )
    bind.execute(sa.text(
        "DELETE FROM group_member WHERE group_id = :dup AND EXISTS ("
        "  SELECT 1 FROM group_member AS t WHERE t.group_id = :target "
        "  AND t.user_id = group_member.user_id AND t.role = group_member.role"
        ")"
    ), params)
    bind.execute(sa.text(
        "UPDATE group_member SET group_id = :target WHERE group_id = :dup"
    ), params)
    bind.execute(sa.text(
        "UPDATE support_group_alias SET group_id = :target WHERE group_id = :dup"
    ), params)
    bind.execute(sa.text(
        "UPDATE support_group SET manager_id = "
        "  (SELECT manager_id FROM support_group WHERE id = :dup) "
        "WHERE id = :target AND manager_id IS NULL "
        "AND (SELECT manager_id FROM support_group WHERE id = :dup) IS NOT NULL"
    ), params)
    bind.execute(sa.text("DELETE FROM support_group WHERE id = :dup"), params)


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if not {"support_group_alias", "support_group", "group_member"} <= tables:
        return
    fk_targets = [(table, column) for table, column in FK_TARGETS if table in tables]

    database_groups = bind.execute(sa.text(
        "SELECT id, tenant_id FROM support_group WHERE lower(name) = 'database'"
    )).fetchall()

    for group_id, tenant_id in database_groups:
        exists = bind.execute(sa.text(
            "SELECT 1 FROM support_group_alias "
            "WHERE tenant_id = :tenant_id AND lower(alias) = 'dba team'"
        ), {"tenant_id": tenant_id}).first()
        if not exists:
            bind.execute(sa.text(
                "INSERT INTO support_group_alias (alias, group_id, tenant_id, created_at) "
                "VALUES ('DBA Team', :group_id, :tenant_id, CURRENT_TIMESTAMP)"
            ), {"group_id": group_id, "tenant_id": tenant_id})

    pairs = bind.execute(sa.text(
        "SELECT g.id AS dup_id, a.group_id AS target_id "
        "FROM support_group_alias a "
        "JOIN support_group g "
        "  ON lower(g.name) = lower(a.alias) "
        " AND g.tenant_id = a.tenant_id "
        " AND g.id != a.group_id"
    )).fetchall()

    for dup_id, target_id in pairs:
        _merge(bind, fk_targets, dup_id, target_id)


def downgrade():
    pass
