"""Monitoring duplicate delivery must be safe across actual database sessions."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app import MonitoringEvent, MonitoringSource, SupportGroup, User, create_api_token, db
from tests.test_architecture_transactions import pg_review  # noqa: F401


def test_parallel_monitoring_delivery_creates_one_record(pg_review, monkeypatch):
    import serviceops_core.web.api as api
    with pg_review.app_context():
        admin = User.query.filter_by(username='admin').one()
        group = SupportGroup.query.filter_by(name='Unix').one()
        token, prefix, digest = create_api_token()
        source = MonitoringSource(name='Concurrent delivery', token_prefix=prefix, token_hash=digest,
                                  assignment_group_id=group.id, created_by_id=admin.id)
        db.session.add(source)
        db.session.commit()
        endpoint = f'/api/v1/monitoring/{source.source_id}/events'
    allocate = api.next_enterprise_number
    def slow_allocate(domain):
        # Widen the real check-then-insert window; no fake database or transaction.
        time.sleep(0.2)
        return allocate(domain)
    monkeypatch.setattr(api, 'next_enterprise_number', slow_allocate)
    started = threading.Barrier(2)
    def deliver():
        started.wait(timeout=10)
        with pg_review.test_client() as client:
            return client.post(endpoint, headers={'Authorization': f'Bearer {token}'}, json={
                'external_id': 'parallel-delivery', 'severity': 'high', 'resource': 'database',
                'summary': 'One alert delivered twice',
            }).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: deliver(), range(2)))
    assert sorted(outcomes) == [200, 201]
    with pg_review.app_context():
        assert MonitoringEvent.query.filter_by(external_id='parallel-delivery').count() == 1
