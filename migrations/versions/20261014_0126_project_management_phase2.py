"""Project management, phase 2 (B-449): resolutions, link types, components,
versions, work logs, votes, stars, views, comment reactions and moved-key
aliases; new columns on project (category, default assignee), work_item
(remaining and spent time, environment, resolution, flag) and
work_item_comment (visibility).

Additive. The downgrade drops the new tables and columns.

Revision ID: 20261014_0126
Revises: 20261014_0125
"""
from alembic import op
import sqlalchemy as sa

revision = "20261014_0126"
down_revision = "20261014_0125"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

NEW_TABLES = (
    "work_item_key_alias", "work_item_comment_reaction", "work_item_view", "project_star", "work_item_vote",
    "work_item_worklog", "work_item_affects_version", "work_item_fix_version", "work_item_component",
    "project_version", "project_component", "work_item_link_type",
)


def _tenant():
    return sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True)


def _when(name, nullable=False):
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade():
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "work_item_resolution" in tables:
        return
    op.create_table(
        "work_item_resolution",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("name", sa.String(60), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_work_item_resolution_name"),
    )
    op.create_table(
        "work_item_link_type",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("name", sa.String(40), nullable=False),
        sa.Column("outward", sa.String(60), nullable=False),
        sa.Column("inward", sa.String(60), nullable=False),
        sa.UniqueConstraint("tenant_id", "name", name="uq_work_item_link_type_name"),
    )
    op.create_table(
        "project_component",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("lead_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("default_assignee", sa.String(20), nullable=False),
        sa.UniqueConstraint("project_id", "name", name="uq_project_component_name"),
    )
    op.create_table(
        "project_version",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("start_date", sa.Date()),
        sa.Column("release_date", sa.Date()),
        sa.Column("released", sa.Boolean(), nullable=False),
        _when("released_at", nullable=True),
        sa.Column("archived", sa.Boolean(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.UniqueConstraint("project_id", "name", name="uq_project_version_name"),
    )
    for table, column, target in (("work_item_component", "component_id", "project_component.id"),
                                  ("work_item_fix_version", "version_id", "project_version.id"),
                                  ("work_item_affects_version", "version_id", "project_version.id")):
        op.create_table(
            table,
            sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True),
            sa.Column(column, sa.Integer(), sa.ForeignKey(target, ondelete="CASCADE"), primary_key=True, index=True),
            _tenant(),
        )
    op.create_table(
        "work_item_worklog",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("author_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False, index=True),
        _when("started_at"),
        sa.Column("minutes", sa.Integer(), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False),
        _when("created_at"),
        _when("updated_at", nullable=True),
    )
    op.create_table(
        "work_item_vote",
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), primary_key=True, index=True),
        _tenant(), _when("created_at"),
    )
    op.create_table(
        "project_star",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("target_type", sa.String(12), primary_key=True),
        sa.Column("target_id", sa.Integer(), primary_key=True),
        _tenant(), _when("created_at"),
    )
    op.create_table(
        "work_item_view",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True),
        _tenant(),
        sa.Column("viewed_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_table(
        "work_item_comment_reaction",
        sa.Column("comment_id", sa.Integer(), sa.ForeignKey("work_item_comment.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("emoji", sa.String(16), primary_key=True),
        _tenant(),
    )
    op.create_table(
        "work_item_key_alias",
        sa.Column("id", sa.Integer(), primary_key=True), _tenant(),
        sa.Column("project_key", sa.String(10), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("tenant_id", "project_key", "number", name="uq_work_item_key_alias"),
    )
    with op.batch_alter_table("project") as batch:
        batch.add_column(sa.Column("category", sa.String(60)))
        batch.add_column(sa.Column("default_assignee", sa.String(20), nullable=False, server_default="unassigned"))
    with op.batch_alter_table("work_item") as batch:
        batch.add_column(sa.Column("remaining_minutes", sa.Integer()))
        batch.add_column(sa.Column("spent_minutes", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("environment", sa.Text(), nullable=False, server_default=""))
        batch.add_column(sa.Column("resolution_id", sa.Integer()))
        batch.add_column(sa.Column("flagged", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.create_foreign_key("work_item_resolution_id_fkey", "work_item_resolution", ["resolution_id"], ["id"])
    with op.batch_alter_table("work_item_comment") as batch:
        batch.add_column(sa.Column("visibility", sa.String(10)))


def downgrade():
    # Inside downgrade so the expand-phase safety check (which ignores the
    # downgrade) does not see these drops as part of the upgrade.
    def _drop_columns(table, columns):
        bind = op.get_bind()
        present = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        columns = [column for column in columns if column in present]
        if not columns:
            return
        if bind.dialect.name == "sqlite":
            with op.batch_alter_table(table, recreate="always") as batch:
                for column in columns:
                    batch.drop_column(column)
            return
        for fk in sa.inspect(bind).get_foreign_keys(table):
            if fk["name"] and set(fk["constrained_columns"]) & set(columns):
                op.drop_constraint(fk["name"], table, type_="foreignkey")
        for column in columns:
            op.drop_column(table, column)

    _drop_columns("work_item_comment", ["visibility"])
    _drop_columns("work_item", ["remaining_minutes", "spent_minutes", "environment", "resolution_id", "flagged"])
    _drop_columns("project", ["category", "default_assignee"])
    for table in NEW_TABLES:
        op.drop_table(table)
    op.drop_table("work_item_resolution")
