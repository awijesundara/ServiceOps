"""Verify quota aggregation against isolated real PostgreSQL."""
from datetime import datetime, timedelta, timezone

from app import AICall, AIConnection, db
from serviceops_core.ai import quota
from tests.test_architecture_transactions import pg_review


def test_provider_usage_case_and_datetime_aggregates_on_postgres(pg_review):
    at = datetime(2026, 10, 25, 4, tzinfo=timezone.utc)
    with pg_review.app_context():
        service = AIConnection(tenant_id=1, name='Review SQL usage', provider='self_hosted',
                               model='test', endpoint='http://localhost:11434',
                               quota_tz='America/Los_Angeles', rpm_limit=2)
        db.session.add(service)
        db.session.flush()
        for seconds in (60, 61, 18000):
            db.session.add(AICall(tenant_id=1, connection_id=service.id,
                started_at=at - timedelta(seconds=seconds), prompt_tokens=2, completion_tokens=3))
        db.session.flush()
        head = quota.headroom(service, quota.recent_calls(1, at), at=at)
        assert (head.rpm_used, head.tpm_used, head.rpd_used) == (1, 5, 3)
        assert head.ok
        db.session.rollback()
