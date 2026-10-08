"""Per-request database cost: batched request metrics, request-scoped caches, and query budgets."""
from contextlib import nullcontext

from flask import has_app_context
from sqlalchemy import event

from app import PlatformSetting, RequestMetricTotal, db, flush_request_metrics, setting_value
from tests.test_app import app, client, login  # noqa: F401 - pytest fixtures


def count_queries(app, action):
    statements = []

    def record(conn, cursor, statement, params, context, executemany):
        statements.append(statement)

    # Reuse an active context so a test_request_context (and its request cache) stays current.
    with nullcontext() if has_app_context() else app.app_context():
        event.listen(db.engine, "before_cursor_execute", record)
        try:
            action()
        finally:
            event.remove(db.engine, "before_cursor_execute", record)
    return statements


def test_request_metrics_are_batched_then_flushed_as_one_increment(client, app):
    with app.app_context():
        RequestMetricTotal.query.delete()
        db.session.commit()
        flush_request_metrics()  # drop anything another test left buffered
        RequestMetricTotal.query.delete()
        db.session.commit()
    app.config["REQUEST_METRIC_FLUSH_SECONDS"] = 3600
    for _ in range(3):
        client.get("/health")
    with app.app_context():
        # Nothing written per request: no row lock is taken on the hot path.
        assert RequestMetricTotal.query.filter_by(method="GET", status="200").first() is None
        flush_request_metrics()
        row = RequestMetricTotal.query.filter_by(method="GET", status="200").one()
        assert row.request_count == 3
        flush_request_metrics()  # empty buffer: a no-op, not a double count
        assert RequestMetricTotal.query.filter_by(method="GET", status="200").one().request_count == 3
    # /metrics flushes its own worker's pending counts before reporting.
    client.get("/health")
    assert b'serviceops_http_requests_total{method="GET",status="200"} 4' in client.get("/metrics").data


def test_settings_load_once_per_request_and_see_writes_made_during_it(app):
    with app.test_request_context("/"):
        before = count_queries(app, lambda: [setting_value(key) for key in ("INSTANCE_NAME", "COMPANY_NAME", "NO_SUCH_KEY")])
        assert sum("FROM platform_setting" in sql for sql in before) == 1
        assert count_queries(app, lambda: setting_value("INSTANCE_NAME")) == []

        db.session.add(PlatformSetting(key="INSTANCE_NAME", value="Ops Hub", encrypted=False))
        db.session.flush()
        assert setting_value("INSTANCE_NAME") == "Ops Hub"
        db.session.rollback()


def test_shared_layout_query_budget(client, app):
    login(client)
    client.get("/help")
    statements = count_queries(app, lambda: client.get("/help"))
    settings = [sql for sql in statements if "FROM platform_setting" in sql]
    tenants = [sql for sql in statements if "FROM tenant" in sql]
    assert len(settings) <= 1, "settings must load in one query per request"
    assert len(tenants) <= 1, "the tenant must load once per request"
    assert len(statements) <= 24, f"{len(statements)} queries for a static help page"
