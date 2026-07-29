"""Add enforced tenant_id columns to approval_gate, approval_vote, and
change_governance. These already only became reachable through a tenant-scoped
parent (approval_chain / ticket) in every existing query path, but per the
same defense-in-depth precedent as ci_relationship.tenant_id (B-253), decision
records this security-sensitive should carry their own enforced column rather
than depend on every future query remembering the join.

Revision ID: 20260729_0025
Revises: 20260729_0024
"""
from alembic import op
import sqlalchemy as sa

revision = "20260729_0025"
down_revision = "20260729_0024"
branch_labels = None
depends_on = None


def _add_backfilled_tenant_column(table, backfill_sql, fk_name, ix_name):
    # Every step here runs inside op.batch_alter_table, matching
    # 20260726_0002's identical add-backfill-constrain sequence: SQLite can't
    # ALTER a column's nullability or add a named constraint/index in place,
    # only via the copy-and-move/batch strategy. This is a no-op wrapper
    # around plain ALTER TABLE on PostgreSQL.
    bind = op.get_bind()
    columns = {col["name"] for col in sa.inspect(bind).get_columns(table)}
    if "tenant_id" in columns:
        return
    with op.batch_alter_table(table) as batch:
        batch.add_column(sa.Column("tenant_id", sa.Integer(), nullable=True))
    op.execute(backfill_sql)
    with op.batch_alter_table(table) as batch:
        batch.alter_column("tenant_id", existing_type=sa.Integer(), nullable=False)
        batch.create_foreign_key(fk_name, "tenant", ["tenant_id"], ["id"])
        batch.create_index(ix_name, ["tenant_id"])


def upgrade():
    _add_backfilled_tenant_column(
        "approval_gate",
        "UPDATE approval_gate SET tenant_id = ("
        "SELECT approval_chain.tenant_id FROM approval_chain "
        "WHERE approval_chain.id = approval_gate.chain_id)",
        "fk_approval_gate_tenant",
        "ix_approval_gate_tenant_id",
    )
    _add_backfilled_tenant_column(
        "approval_vote",
        "UPDATE approval_vote SET tenant_id = ("
        "SELECT approval_chain.tenant_id FROM approval_chain "
        "JOIN approval_gate ON approval_gate.chain_id = approval_chain.id "
        "WHERE approval_gate.id = approval_vote.gate_id)",
        "fk_approval_vote_tenant",
        "ix_approval_vote_tenant_id",
    )
    _add_backfilled_tenant_column(
        "change_governance",
        "UPDATE change_governance SET tenant_id = ("
        "SELECT ticket.tenant_id FROM ticket "
        "WHERE ticket.id = change_governance.ticket_id)",
        "fk_change_governance_tenant",
        "ix_change_governance_tenant_id",
    )


def _drop_tenant_column(table):
    # batch_alter_table: SQLite has no ALTER-based constraint drop support
    # (needs the copy-and-move/batch strategy); this also works unchanged
    # against PostgreSQL. The FK's constraint name is looked up through the
    # inspector rather than hardcoded, because SQLite doesn't reliably
    # preserve/reflect the name Alembic assigned at creation time (see the
    # identical pattern in 20260726_0002's downgrade).
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tenant_fks = [
        fk["name"] for fk in inspector.get_foreign_keys(table)
        if fk["name"] and "tenant_id" in fk.get("constrained_columns", ())
    ]
    tenant_indexes = [
        ix["name"] for ix in inspector.get_indexes(table)
        if ix["name"] and "tenant_id" in ix.get("column_names", ())
    ]
    with op.batch_alter_table(table) as batch:
        for ix_name in tenant_indexes:
            batch.drop_index(ix_name)
        for fk_name in tenant_fks:
            batch.drop_constraint(fk_name, type_="foreignkey")
        batch.drop_column("tenant_id")


def downgrade():
    _drop_tenant_column("change_governance")
    _drop_tenant_column("approval_vote")
    _drop_tenant_column("approval_gate")
