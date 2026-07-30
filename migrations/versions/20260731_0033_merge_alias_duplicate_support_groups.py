"""Merge any SupportGroup that duplicates an existing team-name alias (e.g.
a "DBA" group that predates the "DBA" -> "Database" alias seeded in
20260731_0031) into the alias's target team. Registering the alias alone
only affects future free-text resolution -- it doesn't move records that
already point at the duplicate, which left CIs like a DBA-owned server
pointing at a "DBA" team with no manager, and change approval failing with
"The DBA team requires an active manager." This runs the same merge for
every tenant, for every alias, not just DBA/Database, so any other
already-duplicated team name is fixed too.

Revision ID: 20260731_0033
Revises: 20260731_0032
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0033"
down_revision = "20260731_0032"
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


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if not {"support_group_alias", "support_group", "group_member"} <= tables:
        return
    fk_targets = [(table, column) for table, column in FK_TARGETS if table in tables]

    pairs = bind.execute(sa.text(
        "SELECT g.id AS dup_id, a.group_id AS target_id "
        "FROM support_group_alias a "
        "JOIN support_group g "
        "  ON lower(g.name) = lower(a.alias) "
        " AND g.tenant_id = a.tenant_id "
        " AND g.id != a.group_id"
    )).fetchall()

    for dup_id, target_id in pairs:
        params = {"dup": dup_id, "target": target_id}
        for table, column in fk_targets:
            bind.execute(
                sa.text(f"UPDATE {table} SET {column} = :target WHERE {column} = :dup"),
                params,
            )
        # Drop duplicate-team memberships that would collide with an
        # existing (user, role) membership on the target team, then move
        # the rest.
        bind.execute(sa.text(
            "DELETE FROM group_member WHERE group_id = :dup AND EXISTS ("
            "  SELECT 1 FROM group_member AS t WHERE t.group_id = :target "
            "  AND t.user_id = group_member.user_id AND t.role = group_member.role"
            ")"
        ), params)
        bind.execute(sa.text(
            "UPDATE group_member SET group_id = :target WHERE group_id = :dup"
        ), params)
        # Any other alias pointing at the duplicate should point at the target.
        bind.execute(sa.text(
            "UPDATE support_group_alias SET group_id = :target WHERE group_id = :dup"
        ), params)
        # Adopt the duplicate's manager if the target has none.
        bind.execute(sa.text(
            "UPDATE support_group SET manager_id = "
            "  (SELECT manager_id FROM support_group WHERE id = :dup) "
            "WHERE id = :target AND manager_id IS NULL "
            "AND (SELECT manager_id FROM support_group WHERE id = :dup) IS NOT NULL"
        ), params)
        bind.execute(sa.text("DELETE FROM support_group WHERE id = :dup"), params)


def downgrade():
    pass
