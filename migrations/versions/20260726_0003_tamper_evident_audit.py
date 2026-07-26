"""Add correlated, tamper-evident and append-only audit events.

Revision ID: 20260726_0003
Revises: 20260726_0002
"""
from datetime import timezone
import hashlib
import json
import uuid

from alembic import op
import sqlalchemy as sa

revision = "20260726_0003"
down_revision = "20260726_0002"
branch_labels = None
depends_on = None


def canonical_payload(row):
    created_at = row["created_at"]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return json.dumps({
        "action": row["action"],
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "details": row["details"] or "",
        "event_id": row["event_id"],
        "previous_hash": row["previous_hash"] or "",
        "request_id": row["request_id"],
        "source_ip": "",
        "target": row["target"],
        "tenant_id": row["tenant_id"],
        "user_agent": "",
        "user_id": row["user_id"],
    }, sort_keys=True, separators=(",", ":")).encode()


def upgrade():
    bind = op.get_bind()
    columns = {column["name"] for column in sa.inspect(bind).get_columns("audit")}
    if "event_hash" not in columns:
        with op.batch_alter_table("audit") as batch:
            batch.add_column(sa.Column("event_id", sa.String(length=36), nullable=True))
            batch.add_column(sa.Column("request_id", sa.String(length=36), nullable=True))
            batch.add_column(sa.Column("source_ip", sa.String(length=64), nullable=True))
            batch.add_column(sa.Column("user_agent", sa.String(length=255), nullable=True))
            batch.add_column(sa.Column("integrity_version", sa.String(length=30), nullable=True))
            batch.add_column(sa.Column("previous_hash", sa.String(length=64), nullable=True))
            batch.add_column(sa.Column("event_hash", sa.String(length=64), nullable=True))

        audit = sa.table(
            "audit",
            sa.column("id", sa.Integer),
            sa.column("event_id", sa.String),
            sa.column("user_id", sa.Integer),
            sa.column("action", sa.String),
            sa.column("target", sa.String),
            sa.column("details", sa.Text),
            sa.column("request_id", sa.String),
            sa.column("integrity_version", sa.String),
            sa.column("previous_hash", sa.String),
            sa.column("event_hash", sa.String),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("tenant_id", sa.Integer),
        )
        rows = bind.execute(sa.select(audit).order_by(
            audit.c.tenant_id, audit.c.id
        )).mappings().all()
        previous_by_tenant = {}
        namespace = uuid.UUID("a3827924-b124-4db0-92f6-4ccbd780fc5e")
        for source in rows:
            row = dict(source)
            row["event_id"] = str(uuid.uuid5(namespace, f"audit:{row['id']}"))
            row["request_id"] = str(uuid.uuid5(namespace, f"request:{row['id']}"))
            row["previous_hash"] = previous_by_tenant.get(row["tenant_id"], "")
            row["integrity_version"] = "legacy-sha256-v1"
            row["event_hash"] = hashlib.sha256(canonical_payload(row)).hexdigest()
            bind.execute(
                audit.update().where(audit.c.id == row["id"]).values(
                    event_id=row["event_id"],
                    request_id=row["request_id"],
                    integrity_version=row["integrity_version"],
                    previous_hash=row["previous_hash"],
                    event_hash=row["event_hash"],
                )
            )
            previous_by_tenant[row["tenant_id"]] = row["event_hash"]

        with op.batch_alter_table("audit") as batch:
            batch.alter_column("event_id", existing_type=sa.String(length=36), nullable=False)
            batch.alter_column("request_id", existing_type=sa.String(length=36), nullable=False)
            batch.alter_column(
                "integrity_version", existing_type=sa.String(length=30), nullable=False
            )
            batch.alter_column(
                "previous_hash", existing_type=sa.String(length=64), nullable=False
            )
            batch.alter_column(
                "event_hash", existing_type=sa.String(length=64), nullable=False
            )
            batch.create_unique_constraint("uq_audit_event_id", ["event_id"])
            batch.create_unique_constraint("uq_audit_event_hash", ["event_hash"])
            batch.create_index("ix_audit_request_id", ["request_id"])

    if bind.dialect.name == "postgresql":
        op.execute("""
            CREATE OR REPLACE FUNCTION serviceops_reject_audit_mutation()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'ServiceOps audit events are append-only';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER serviceops_audit_append_only
            BEFORE UPDATE OR DELETE ON audit
            FOR EACH ROW EXECUTE FUNCTION serviceops_reject_audit_mutation()
        """)
    elif bind.dialect.name == "sqlite":
        op.execute("""
            CREATE TRIGGER serviceops_audit_no_update
            BEFORE UPDATE ON audit BEGIN
                SELECT RAISE(ABORT, 'ServiceOps audit events are append-only');
            END
        """)
        op.execute("""
            CREATE TRIGGER serviceops_audit_no_delete
            BEFORE DELETE ON audit BEGIN
                SELECT RAISE(ABORT, 'ServiceOps audit events are append-only');
            END
        """)


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS serviceops_audit_append_only ON audit")
        op.execute("DROP FUNCTION IF EXISTS serviceops_reject_audit_mutation()")
    elif bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS serviceops_audit_no_update")
        op.execute("DROP TRIGGER IF EXISTS serviceops_audit_no_delete")
    index_names = {
        index["name"] for index in sa.inspect(bind).get_indexes("audit")
    }
    with op.batch_alter_table("audit") as batch:
        if "ix_audit_request_id" in index_names:
            batch.drop_index("ix_audit_request_id")
        batch.drop_column("event_hash")
        batch.drop_column("previous_hash")
        batch.drop_column("integrity_version")
        batch.drop_column("user_agent")
        batch.drop_column("source_ip")
        batch.drop_column("request_id")
        batch.drop_column("event_id")
