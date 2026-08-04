"""Replace the previous 20260803_0052 "lock a user's role" mechanism (never
released to production, reverted per direct product feedback) with real
multi-role support: a user can hold more than one role at once (e.g. both
"manager" and "admin") and switch which one they're acting as. Adds
user_role_grant (the roles a user currently holds) and
managed_role_grant (which automatic source -- AD/SSO group mapping or team
responsibility -- currently justifies a grant, so a resync can safely
revoke one no longer justified without touching a manually-granted role).
Backfills every existing user's current `role` as their first grant.

Revision ID: 20260804_0053
Revises: 20260803_0052
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "20260804_0053"
down_revision = "20260803_0052"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    existing_user_columns = {col["name"] for col in inspector.get_columns("user")}
    if "role_locked" in existing_user_columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.drop_column("role_locked")

    if not inspector.has_table("user_role_grant"):
        op.create_table(
            "user_role_grant",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False),
            sa.Column(
                "created_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint("user_id", "role", name="uq_user_role_grant"),
        )

    if not inspector.has_table("managed_role_grant"):
        op.create_table(
            "managed_role_grant",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False),
            sa.Column("source", sa.String(length=30), nullable=False),
            sa.Column("detail", sa.String(length=500)),
            sa.Column(
                "synchronized_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint("user_id", "role", "source", name="uq_managed_role_grant"),
        )

    # Backfill: every existing user's current base role becomes their first
    # grant, so nothing changes for anyone until the next AD/SSO login,
    # team-manager assignment, or manual admin grant.
    user_table = sa.table("user", sa.column("id", sa.Integer), sa.column("role", sa.String))
    grant_table = sa.table(
        "user_role_grant", sa.column("user_id", sa.Integer), sa.column("role", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    users = bind.execute(sa.select(user_table.c.id, user_table.c.role)).fetchall()
    existing_grants = {
        (row.user_id, row.role)
        for row in bind.execute(sa.select(grant_table.c.user_id, grant_table.c.role))
    }
    # Set created_at explicitly rather than relying on the column's
    # server_default -- sa.func.now() renders as dialect-generic "now()" in
    # a plain bulk INSERT, which SQLite (used by the test suite) does not
    # understand as a DEFAULT expression.
    backfilled_at = datetime.now(timezone.utc)
    to_insert = [
        {"user_id": row.id, "role": row.role, "created_at": backfilled_at}
        for row in users
        if row.role and (row.id, row.role) not in existing_grants
    ]
    if to_insert:
        op.bulk_insert(grant_table, to_insert)


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if inspector.has_table("managed_role_grant"):
        op.drop_table("managed_role_grant")
    if inspector.has_table("user_role_grant"):
        op.drop_table("user_role_grant")

    existing_user_columns = {col["name"] for col in inspector.get_columns("user")}
    if "role_locked" not in existing_user_columns:
        with op.batch_alter_table("user") as batch_op:
            batch_op.add_column(
                sa.Column("role_locked", sa.Boolean(), nullable=False, server_default=sa.false())
            )
