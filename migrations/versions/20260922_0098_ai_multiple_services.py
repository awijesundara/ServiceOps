"""Several AI services per organization, with routing and privacy rules.

Adds the ai_connection table (one row per AI service), routing and sensitive-data
settings on ai_configuration, and route records on ai_run / ai_message. The existing
single provider configuration is copied into one connection so nothing changes for
current installations. Everything is additive; the previous release keeps working.

Revision ID: 20260922_0098
Revises: 20260921_0097
"""
import uuid

from alembic import op
import sqlalchemy as sa

revision = "20260922_0098"
down_revision = "20260921_0097"
branch_labels = None
depends_on = None
serviceops_migration_phase = "expand"

CONFIG_COLUMNS = (
    ("routing_mode", sa.String(20), "smart"),
    ("external_scope", sa.String(20), "not_sensitive"),
    ("detect_personal", sa.Boolean(), sa.true()),
    ("detect_credentials", sa.Boolean(), sa.true()),
    ("detect_financial", sa.Boolean(), sa.true()),
    ("sensitive_terms", sa.Text(), ""),
)


def _columns(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for name, kind, default in CONFIG_COLUMNS:
        if name not in _columns("ai_configuration"):
            op.add_column("ai_configuration", sa.Column(name, kind, nullable=False, server_default=default))
    for name, kind, default in (("connection_id", sa.String(36), None), ("route_json", sa.Text(), "{}")):
        if name not in _columns("ai_run"):
            op.add_column("ai_run", sa.Column(name, kind, nullable=default is None, server_default=default))
    if "route_json" not in _columns("ai_message"):
        op.add_column("ai_message", sa.Column("route_json", sa.Text(), nullable=False, server_default="{}"))
    if "ai_connection" not in inspector.get_table_names():
        op.create_table(
            "ai_connection",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenant.id"), nullable=False),
            sa.Column("name", sa.String(80), nullable=False),
            sa.Column("provider", sa.String(30), nullable=False, server_default="self_hosted"),
            sa.Column("endpoint", sa.String(500), nullable=False, server_default=""),
            sa.Column("model", sa.String(160), nullable=False, server_default=""),
            sa.Column("key_encrypted", sa.Text(), nullable=False, server_default=""),
            sa.Column("capabilities_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
            sa.Column("weight", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_failure_at", sa.DateTime(timezone=True)),
            sa.Column("last_success_at", sa.DateTime(timezone=True)),
            sa.Column("last_test_ok", sa.Boolean()),
            sa.Column("last_test_at", sa.DateTime(timezone=True)),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("tenant_id", "name", name="uq_ai_connection_name"),
        )
        op.create_index("ix_ai_connection_tenant_id", "ai_connection", ["tenant_id"])
    # Carry the current single configuration over as the first connection.
    rows = bind.execute(sa.text(
        "SELECT tenant_id, provider, endpoint, model, key_encrypted, capabilities_json FROM ai_configuration "
        "WHERE model <> '' AND tenant_id NOT IN (SELECT tenant_id FROM ai_connection)")).fetchall()
    for tenant_id, provider, endpoint, model, key, capabilities in rows:
        bind.execute(sa.text(
            "INSERT INTO ai_connection (id, tenant_id, name, provider, endpoint, model, key_encrypted, capabilities_json) "
            "VALUES (:id, :tenant, :name, :provider, :endpoint, :model, :key, :caps)"),
            {"id": str(uuid.uuid4()), "tenant": tenant_id, "name": "Primary", "provider": provider, "endpoint": endpoint,
             "model": model, "key": key, "caps": capabilities or "{}"})


def downgrade():
    bind = op.get_bind()
    if "ai_connection" in sa.inspect(bind).get_table_names():
        extra = bind.execute(sa.text(
            "SELECT COUNT(*) FROM (SELECT tenant_id FROM ai_connection GROUP BY tenant_id HAVING COUNT(*) > 1) t")).scalar()
        if extra:
            raise RuntimeError("Refusing to drop AI services: an organization has more than one. Remove the extras first.")
        op.drop_table("ai_connection")
    with op.batch_alter_table("ai_message") as batch:
        batch.drop_column("route_json")
    with op.batch_alter_table("ai_run") as batch:
        batch.drop_column("route_json")
        batch.drop_column("connection_id")
    with op.batch_alter_table("ai_configuration") as batch:
        for name, _, _ in CONFIG_COLUMNS:
            batch.drop_column(name)
