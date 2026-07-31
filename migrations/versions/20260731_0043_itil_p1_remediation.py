"""ITIL 4 gap-analysis P1 remediation: structured post-incident review
fields on MajorIncidentProfile, and a calculated/overridable risk score on
ChangeGovernance.

Revision ID: 20260731_0043
Revises: 20260731_0042
"""
from alembic import op
import sqlalchemy as sa

revision = "20260731_0043"
down_revision = "20260731_0042"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "major_incident_profile" in existing:
        columns = {c["name"] for c in inspector.get_columns("major_incident_profile")}
        with op.batch_alter_table("major_incident_profile") as batch_op:
            if "review_what_went_well" not in columns:
                batch_op.add_column(sa.Column("review_what_went_well", sa.Text(), nullable=True))
            if "review_what_went_poorly" not in columns:
                batch_op.add_column(sa.Column("review_what_went_poorly", sa.Text(), nullable=True))
            if "review_follow_up_actions" not in columns:
                batch_op.add_column(sa.Column("review_follow_up_actions", sa.Text(), nullable=True))
            if "reviewed_by_id" not in columns:
                batch_op.add_column(sa.Column("reviewed_by_id", sa.Integer(), nullable=True))
            if "reviewed_at" not in columns:
                batch_op.add_column(sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))

    if "change_governance" in existing:
        columns = {c["name"] for c in inspector.get_columns("change_governance")}
        with op.batch_alter_table("change_governance") as batch_op:
            if "risk_score_overridden" not in columns:
                batch_op.add_column(
                    sa.Column("risk_score_overridden", sa.Boolean(), nullable=False, server_default=sa.false())
                )
            if "risk_score_override_reason" not in columns:
                batch_op.add_column(sa.Column("risk_score_override_reason", sa.Text(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "change_governance" in existing:
        columns = {c["name"] for c in inspector.get_columns("change_governance")}
        with op.batch_alter_table("change_governance") as batch_op:
            if "risk_score_override_reason" in columns:
                batch_op.drop_column("risk_score_override_reason")
            if "risk_score_overridden" in columns:
                batch_op.drop_column("risk_score_overridden")

    if "major_incident_profile" in existing:
        columns = {c["name"] for c in inspector.get_columns("major_incident_profile")}
        with op.batch_alter_table("major_incident_profile") as batch_op:
            if "reviewed_at" in columns:
                batch_op.drop_column("reviewed_at")
            if "reviewed_by_id" in columns:
                batch_op.drop_column("reviewed_by_id")
            if "review_follow_up_actions" in columns:
                batch_op.drop_column("review_follow_up_actions")
            if "review_what_went_poorly" in columns:
                batch_op.drop_column("review_what_went_poorly")
            if "review_what_went_well" in columns:
                batch_op.drop_column("review_what_went_well")
