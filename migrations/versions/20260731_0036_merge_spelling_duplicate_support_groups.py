"""Merge SupportGroup rows that are spelling/formatting variants of the same
team (e.g. "SSD" / "SSD Team", "Unix" / "Unix Team", "CoreApps" / "Core
apps" / "CoreApps team") -- these accumulated from repeated CSV imports
using slightly different Owner-column text over time, and showed up as
separate, confusing entries in every team dropdown. Unlike
20260731_0033 (which merges groups matching an admin-curated
SupportGroupAlias for genuinely different names, e.g. "DBA" vs
"Database"), this collapses same-word variants automatically: case,
whitespace, punctuation, and a trailing "team"/"teams" word are ignored.
Matches app.py's support_group_dedup_key/find_and_merge_duplicate_groups,
which now also runs this sweep after every CSV import.

Revision ID: 20260731_0036
Revises: 20260731_0035
"""
import re

from alembic import op
import sqlalchemy as sa

revision = "20260731_0036"
down_revision = "20260731_0035"
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

_SUFFIX_RE = re.compile(r"\bteams?\b")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]")


def _dedup_key(name):
    return _NON_ALNUM_RE.sub("", _SUFFIX_RE.sub("", (name or "").casefold()))


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
    if not {"support_group", "group_member"} <= tables:
        return
    fk_targets = [(table, column) for table, column in FK_TARGETS if table in tables]

    rows = bind.execute(sa.text(
        "SELECT id, name, tenant_id, manager_id FROM support_group ORDER BY id"
    )).fetchall()

    clusters = {}
    for row in rows:
        clusters.setdefault((row.tenant_id, _dedup_key(row.name)), []).append(row)

    for members in clusters.values():
        if len(members) < 2:
            continue
        canonical = sorted(members, key=lambda r: (r.manager_id is None, r.id))[0]
        for duplicate in members:
            if duplicate.id != canonical.id:
                _merge(bind, fk_targets, duplicate.id, canonical.id)


def downgrade():
    pass
