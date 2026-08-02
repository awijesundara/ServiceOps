"""ISO 27001:2022 gap remediation: TOTP MFA for admin/CCB accounts (A.8.5)
and a general per-IP/per-account web rate limiter for unauthenticated
routes such as /login (A.8.16), generalized from the existing
api_rate_limit_window pattern. See user_requires_mfa_by_policy(),
route_rate_limit() in app.py.

Revision ID: 20260802_0051
Revises: 20260802_0050
"""
from alembic import op
import sqlalchemy as sa

revision = "20260802_0051"
down_revision = "20260802_0050"
branch_labels = None
depends_on = None

MFA_COLUMNS = [
    ("mfa_secret_encrypted", sa.Text(), True),
    ("mfa_enabled", sa.Boolean(), False),
    ("mfa_enrolled_at", sa.DateTime(timezone=True), True),
    ("mfa_backup_codes_json", sa.Text(), True),
]


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("user")}
    with op.batch_alter_table("user") as batch_op:
        for name, col_type, nullable in MFA_COLUMNS:
            if name in existing:
                continue
            if name == "mfa_enabled":
                batch_op.add_column(sa.Column(
                    name, col_type, nullable=False, server_default=sa.false()
                ))
            else:
                batch_op.add_column(sa.Column(name, col_type, nullable=nullable))

    if not inspector.has_table("route_rate_limit_window"):
        op.create_table(
            "route_rate_limit_window",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("key", sa.String(length=160), nullable=False, index=True),
            sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
            sa.Column("request_count", sa.Integer(), nullable=False, server_default="0"),
            sa.UniqueConstraint("key", "window_start", name="uq_route_rate_limit_window"),
        )


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("route_rate_limit_window"):
        op.drop_table("route_rate_limit_window")

    existing = {col["name"] for col in inspector.get_columns("user")}
    with op.batch_alter_table("user") as batch_op:
        for name, _col_type, _nullable in reversed(MFA_COLUMNS):
            if name in existing:
                batch_op.drop_column(name)
