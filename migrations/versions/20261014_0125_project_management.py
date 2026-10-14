"""Project management, phase 1 (B-443): projects, members, statuses and
work items with assignees, watchers, labels, comments, history and links;
attachments may belong to a work item.

Additive: new tables and one nullable column. The downgrade drops them.

Revision ID: 20261014_0125
Revises: 20261013_0124
"""
from alembic import op
import sqlalchemy as sa

revision = "20261014_0125"
down_revision = "20261013_0124"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"


def _tenant():
    return sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False, index=True)


def _created(name="created_at"):
    return sa.Column(name, sa.DateTime(timezone=True), nullable=False)


def upgrade():
    bind = op.get_bind()
    if "project" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "project",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("key", sa.String(10), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("lead_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("color", sa.String(7), nullable=False),
        sa.Column("visibility", sa.String(10), nullable=False),
        sa.Column("next_number", sa.Integer(), nullable=False),
        sa.Column("archived_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        _created(),
        _created("updated_at"),
        sa.UniqueConstraint("tenant_id", "key", name="uq_project_tenant_key"),
    )
    op.create_table(
        "project_member",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False, index=True),
        sa.Column("role", sa.String(10), nullable=False),
        _created("added_at"),
        sa.UniqueConstraint("project_id", "user_id", name="uq_project_member_user"),
    )
    op.create_table(
        "project_status",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(60), nullable=False),
        sa.Column("category", sa.String(12), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("wip_limit", sa.Integer()),
        sa.UniqueConstraint("project_id", "name", name="uq_project_status_name"),
    )
    op.create_table(
        "work_item",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("project.id", ondelete="CASCADE"), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("item_type", sa.String(10), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status_id", sa.Integer(), sa.ForeignKey("project_status.id"), nullable=False),
        sa.Column("priority", sa.String(10), nullable=False),
        sa.Column("reporter_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("parent_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="SET NULL"), index=True),
        sa.Column("rank", sa.Float(), nullable=False),
        sa.Column("start_date", sa.Date()),
        sa.Column("due_date", sa.Date(), index=True),
        sa.Column("story_points", sa.Float()),
        sa.Column("estimate_minutes", sa.Integer()),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        _created(),
        _created("updated_at"),
        sa.UniqueConstraint("project_id", "number", name="uq_work_item_project_number"),
    )
    op.create_index("ix_work_item_project_status_rank", "work_item", ["project_id", "status_id", "rank"])
    for table in ("work_item_assignee", "work_item_watcher"):
        op.create_table(
            table,
            sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), primary_key=True, index=True),
            _tenant(),
        )
    op.create_table(
        "work_item_label",
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("label", sa.String(60), primary_key=True),
        _tenant(),
    )
    op.create_table(
        "work_item_comment",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        _created(),
        sa.Column("edited_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "work_item_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("work_item_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("user.id")),
        sa.Column("field", sa.String(40), nullable=False),
        sa.Column("old_value", sa.Text()),
        sa.Column("new_value", sa.Text()),
        _created(),
    )
    op.create_table(
        "work_item_link",
        sa.Column("id", sa.Integer(), primary_key=True),
        _tenant(),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("work_item.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("link_type", sa.String(12), nullable=False),
        sa.Column("target_type", sa.String(12), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id")),
        _created(),
        sa.UniqueConstraint("source_id", "link_type", "target_type", "target_id", name="uq_work_item_link"),
    )
    op.create_index("ix_work_item_link_target", "work_item_link", ["target_type", "target_id"])
    with op.batch_alter_table("file_attachment") as batch:
        batch.add_column(sa.Column("work_item_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("file_attachment_work_item_id_fkey", "work_item", ["work_item_id"], ["id"],
                                 ondelete="CASCADE")
        batch.create_index("ix_file_attachment_work_item_id", ["work_item_id"])


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    # Names differ between a migrated database and a fresh one built from the
    # models by the baseline revision, so look them up.
    indexes = [index["name"] for index in inspector.get_indexes("file_attachment")
               if index["column_names"] == ["work_item_id"]]
    foreign_keys = [fk["name"] for fk in inspector.get_foreign_keys("file_attachment")
                    if fk["constrained_columns"] == ["work_item_id"] and fk["name"]]
    for name in indexes:
        op.drop_index(name, table_name="file_attachment")
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("file_attachment", recreate="always") as batch:
            batch.drop_column("work_item_id")
    else:
        for name in foreign_keys:
            op.drop_constraint(name, "file_attachment", type_="foreignkey")
        op.drop_column("file_attachment", "work_item_id")
    for table in ("work_item_link", "work_item_history", "work_item_comment", "work_item_label",
                  "work_item_watcher", "work_item_assignee", "work_item", "project_status", "project_member",
                  "project"):
        op.drop_table(table)
