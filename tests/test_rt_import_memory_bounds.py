"""Memory bounds of the Request Tracker import in the background worker: a single huge ticket must not
take the worker down, and if the worker is killed anyway the job must not crash-loop forever."""
import base64
import json
import threading

from app import RTImportJob, User, db, process_rt_import_jobs
from serviceops_core import rt_import
from serviceops_core.rt_import import import_from_rt
from tests.test_app import app  # noqa: F401 - fixture
from tests.test_rt_import import FakeRTSession, enable_rt, make_ticket


def _admin_id():
    return User.query.filter_by(username="admin").one().id


def test_attachments_are_downloaded_one_at_a_time(app, monkeypatch):
    active, peak, lock = [0], [0], threading.Lock()

    class _Counting(FakeRTSession):
        def get(self, url, params=None, timeout=None, **kwargs):
            if "/REST/2.0/attachment/" in url:
                with lock:
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                try:
                    return super().get(url, params=params, timeout=timeout, **kwargs)
                finally:
                    with lock:
                        active[0] -= 1
            return super().get(url, params=params, timeout=timeout, **kwargs)

    with app.app_context():
        pdf = base64.b64encode(b"%PDF-1.4 small").decode()
        meta = {str(7000 + i): {"ContentType": "application/pdf", "Filename": f"f{i}.pdf",
                                "ContentEncoding": "base64", "Content": pdf} for i in range(6)}
        kwargs = dict(tickets=[make_ticket(70, "Six files", requestor_ids=["9"])], queues={"1": "General"},
                      users={"9": {"EmailAddress": "ida@example.test", "RealName": "Ida"}},
                      history={"70": [{"id": "700"}]},
                      transactions={"700": {"Type": "Create", "Content": "files", "Creator": {"id": "9"}}},
                      transaction_attachments={"700": [{"id": k} for k in meta]}, attachment_meta=meta)
        enable_rt(monkeypatch, **kwargs)
        result = import_from_rt(1, _admin_id(), session_factory=lambda b, t: _Counting(**kwargs))
        assert result["attachments_imported"] == 6, result["errors"]
        assert peak[0] == 1


def test_an_oversized_attachment_response_is_skipped_before_it_is_parsed(app, monkeypatch):
    monkeypatch.setattr(rt_import, "_MAX_ATTACHMENT_BYTES", 300)
    with app.app_context():
        big = base64.b64encode(b"%PDF-" + b"x" * 5000).decode()
        factory = enable_rt(
            monkeypatch, tickets=[make_ticket(71, "Huge file", requestor_ids=["9"])], queues={"1": "General"},
            users={"9": {"EmailAddress": "jo@example.test", "RealName": "Jo"}},
            history={"71": [{"id": "710"}]},
            transactions={"710": {"Type": "Create", "Content": "see file", "Creator": {"id": "9"}}},
            transaction_attachments={"710": [{"id": "7100"}]},
            attachment_meta={"7100": {"ContentType": "application/pdf", "Filename": "huge.pdf",
                                      "ContentEncoding": "base64", "Content": big}})
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 1 and result["attachments_imported"] == 0
        assert any("larger than" in e for e in result["errors"])


def test_a_job_that_keeps_killing_the_worker_stops_and_names_the_ticket(app):
    with app.app_context():
        # A slice was in flight on RT #4242 when the worker died, three times over.
        job = RTImportJob(tenant_id=1, actor_user_id=_admin_id(), search_query="id > 0", dry_run=False,
                          status="Running", result_json=json.dumps({"records_created": 10,
                                                                     "_worker": {"inflight": True, "ticket": "4242", "crashes": 2}}))
        db.session.add(job)
        db.session.commit()
        process_rt_import_jobs()
        db.session.expire_all()
        job = db.session.get(RTImportJob, job.id)
        assert job.status == "Failed"
        assert "RT #4242" in job.error and 'id != 4242' in job.error


def test_one_crash_is_resumed_not_failed(app, monkeypatch):
    with app.app_context():
        factory = enable_rt(monkeypatch, tickets=[make_ticket(72, "Fine", requestor_ids=["9"])], queues={"1": "General"},
                            users={"9": {"EmailAddress": "kai@example.test", "RealName": "Kai"}})
        monkeypatch.setattr(rt_import, "_rt_session", factory)
        real = rt_import.import_from_rt
        monkeypatch.setattr(rt_import, "import_from_rt", lambda *a, **k: real(*a, **dict(k, session_factory=factory)))
        job = RTImportJob(tenant_id=1, actor_user_id=_admin_id(), search_query="id > 0", dry_run=False,
                          status="Running", result_json=json.dumps({"_worker": {"inflight": True, "ticket": "72"}}))
        db.session.add(job)
        db.session.commit()
        process_rt_import_jobs()
        db.session.expire_all()
        job = db.session.get(RTImportJob, job.id)
        assert job.status == "Completed", job.error
        assert json.loads(job.result_json)["_worker"] == {"crashes": 1}


def test_the_history_log_stops_growing_at_the_description_limit(app, monkeypatch):
    monkeypatch.setattr(rt_import, "_MAX_LOG_CHARS", 500)
    with app.app_context():
        transactions = {str(800 + i): {"Type": "Correspond", "Content": "y" * 400, "Creator": {"id": "9"}} for i in range(120)}
        factory = enable_rt(
            monkeypatch, tickets=[make_ticket(73, "Chatty", requestor_ids=["9"])], queues={"1": "General"},
            users={"9": {"EmailAddress": "lu@example.test", "RealName": "Lu"}},
            history={"73": [{"id": k} for k in transactions]}, transactions=transactions)
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 1 and result["comments_imported"] == 120
