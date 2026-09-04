"""Add bounded LDAP profile intelligence, login metadata and approval absence delegation.

Revision ID: 20260904_0084
Revises: 20260814_0083
"""
from alembic import op
import sqlalchemy as sa

revision = "20260904_0084"
down_revision = "20260814_0083"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    mapping_columns = {column["name"] for column in inspector.get_columns("directory_group_mapping")}
    if "tenant_id" not in mapping_columns:
        with op.batch_alter_table("directory_group_mapping") as batch_op:
            batch_op.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
        op.execute(sa.text(
            "UPDATE directory_group_mapping SET tenant_id = "
            "(SELECT tenant_id FROM support_group WHERE support_group.id = directory_group_mapping.support_group_id)"
        ))
        inspector = sa.inspect(bind)
        unique_constraints = inspector.get_unique_constraints("directory_group_mapping")
        with op.batch_alter_table("directory_group_mapping") as batch_op:
            for constraint in unique_constraints:
                if constraint.get("column_names") == ["directory_group"] and constraint.get("name"):
                    batch_op.drop_constraint(constraint["name"], type_="unique")
            batch_op.alter_column("tenant_id", nullable=False)
            batch_op.create_foreign_key(
                "fk_directory_group_mapping_tenant_id", "tenant", ["tenant_id"], ["id"]
            )
            batch_op.create_unique_constraint(
                "uq_directory_group_mapping_tenant_group", ["tenant_id", "directory_group"]
            )
            batch_op.create_index("ix_directory_group_mapping_tenant_id", ["tenant_id"])
    managed_columns = {column["name"] for column in inspector.get_columns("directory_managed_membership")}
    if "tenant_id" not in managed_columns:
        with op.batch_alter_table("directory_managed_membership") as batch_op:
            batch_op.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
        op.execute(sa.text(
            "UPDATE directory_managed_membership SET tenant_id = "
            "(SELECT tenant_id FROM support_group WHERE support_group.id = directory_managed_membership.group_id)"
        ))
        with op.batch_alter_table("directory_managed_membership") as batch_op:
            batch_op.alter_column("tenant_id", nullable=False)
            batch_op.create_foreign_key(
                "fk_directory_managed_membership_tenant_id", "tenant", ["tenant_id"], ["id"]
            )
            batch_op.create_unique_constraint(
                "uq_directory_managed_membership_owner", ["tenant_id", "user_id", "group_id"]
            )
            batch_op.create_index("ix_directory_managed_membership_tenant_id", ["tenant_id"])
    if "directory_profile" not in tables:
        op.create_table(
            "directory_profile",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("profile_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("groups_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("synchronized_at", sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint("user_id", name="uq_directory_profile_user_id"),
        )
        op.create_index("ix_directory_profile_user_id", "directory_profile", ["user_id"])
        op.create_index("ix_directory_profile_tenant_id", "directory_profile", ["tenant_id"])
    if "approval_delegation" not in tables:
        op.create_table(
            "approval_delegation",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("from_user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("to_user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reason", sa.String(length=500), nullable=False, server_default=""),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.CheckConstraint("ends_at > starts_at", name="ck_approval_delegation_window"),
            sa.CheckConstraint("from_user_id <> to_user_id", name="ck_approval_delegation_distinct_users"),
        )
        op.create_index("ix_approval_delegation_from_user_id", "approval_delegation", ["from_user_id"])
        op.create_index("ix_approval_delegation_to_user_id", "approval_delegation", ["to_user_id"])
        op.create_index("ix_approval_delegation_tenant_id", "approval_delegation", ["tenant_id"])
    session_columns = {column["name"] for column in inspector.get_columns("user_session")}
    with op.batch_alter_table("user_session") as batch_op:
        if "client_hostname" not in session_columns:
            batch_op.add_column(sa.Column("client_hostname", sa.String(length=255)))
        if "device_label" not in session_columns:
            batch_op.add_column(sa.Column("device_label", sa.String(length=160)))
        if "client_language" not in session_columns:
            batch_op.add_column(sa.Column("client_language", sa.String(length=120)))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    session_columns = {column["name"] for column in inspector.get_columns("user_session")}
    with op.batch_alter_table("user_session") as batch_op:
        for column in ("client_language", "device_label", "client_hostname"):
            if column in session_columns:
                batch_op.drop_column(column)
    if "approval_delegation" in tables:
        op.drop_table("approval_delegation")
    if "directory_profile" in tables:
        op.drop_table("directory_profile")
    # Indexes are independent schema objects on SQLite, so remove them before
    # batch table recreation; otherwise Alembic tries to recreate an index for
    # the column that the batch just removed.
    managed_indexes = {
        item["name"] for item in sa.inspect(bind).get_indexes("directory_managed_membership")
    }
    if "ix_directory_managed_membership_tenant_id" in managed_indexes:
        op.drop_index(
            "ix_directory_managed_membership_tenant_id",
            table_name="directory_managed_membership",
        )
    with op.batch_alter_table("directory_managed_membership") as batch_op:
        batch_op.drop_column("tenant_id")
    mapping_indexes = {
        item["name"] for item in sa.inspect(bind).get_indexes("directory_group_mapping")
    }
    if "ix_directory_group_mapping_tenant_id" in mapping_indexes:
        op.drop_index(
            "ix_directory_group_mapping_tenant_id",
            table_name="directory_group_mapping",
        )
    with op.batch_alter_table("directory_group_mapping") as batch_op:
        batch_op.drop_column("tenant_id")
        batch_op.create_unique_constraint(
            "uq_directory_group_mapping_directory_group", ["directory_group"]
        )
