"""Crash scenarios for the Request Tracker import: whatever a real RT instance
returns, and however long the import takes, it must not take the background
worker down, poison the other tickets, or leave a job stuck forever.
"""
import json
import time

import pytest

from app import EnterpriseRecord, RTImportJob, Tenant, User, db, process_rt_import_jobs
from serviceops_core import rt_import
from serviceops_core.rt_import import import_from_rt
from tests.test_app import app  # noqa: F401 - fixture
from tests.test_rt_import import FakeResponse, FakeRTSession, enable_rt, make_ticket


def _admin_id():
    return User.query.filter_by(username="admin").one().id


class _HtmlForOneTicket(FakeRTSession):
    """An RT behind a proxy that answers one ticket with an HTML error page."""

    def __init__(self, bad_id, **kwargs):
        super().__init__(**kwargs)
        self.bad_id = bad_id

    def get(self, url, params=None, timeout=None, **kwargs):
        if url.endswith(f"/REST/2.0/ticket/{self.bad_id}"):
            return FakeResponse(None, raw=b"<html><body>Login required</body></html>")
        return super().get(url, params=params, timeout=timeout, **kwargs)


def test_html_answer_for_one_ticket_fails_only_that_ticket(app, monkeypatch):
    with app.app_context():
        tickets = [make_ticket(1, "Good one", requestor_ids=["9"]), make_ticket(2, "Behind a login page"),
                   make_ticket(3, "Another good one", requestor_ids=["9"])]
        enable_rt(monkeypatch, tickets=[], queues={}, users={})
        users = {"9": {"EmailAddress": "ann@example.test", "RealName": "Ann"}}
        result = import_from_rt(1, _admin_id(), session_factory=lambda base, token: _HtmlForOneTicket(
            "2", tickets=tickets, queues={"1": "General"}, users=users))
        assert result["records_created"] == 2
        assert any("RT #2" in e and "non-JSON" in e for e in result["errors"])
        assert EnterpriseRecord.query.filter_by(external_source="rt").count() == 2


def test_html_answer_to_the_search_is_reported_not_raised(app, monkeypatch):
    class _HtmlSearch(FakeRTSession):
        def get(self, url, params=None, timeout=None, **kwargs):
            return FakeResponse(None, raw=b"<!doctype html><title>502 Bad Gateway</title>")

    with app.app_context():
        enable_rt(monkeypatch, tickets=[], queues={}, users={})
        result = import_from_rt(1, _admin_id(), session_factory=lambda b, t: _HtmlSearch([], {}, {}))
        assert result["records_created"] == 0
        assert any("non-JSON" in e for e in result["errors"])


def test_nul_characters_and_overlong_names_are_cleaned(app, monkeypatch):
    with app.app_context():
        ticket = make_ticket(10, "Disk\x00 full", requestor_ids=["9"])
        factory = enable_rt(monkeypatch, tickets=[ticket], queues={"1": "Ops\x00" + "Q" * 300},
                            users={"9": {"EmailAddress": "long@example.test", "RealName": "N" * 500}})
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 1, result["errors"]
        record = EnterpriseRecord.query.filter_by(external_id="10").one()
        assert "\x00" not in record.title and record.title == "Disk full"
        assert len(User.query.filter_by(email="long@example.test").one().name) <= 120


def test_requester_from_another_tenant_falls_back_to_placeholder(app, monkeypatch):
    with app.app_context():
        other = Tenant(slug="other-co", name="Other Co", active=True)
        db.session.add(other)
        db.session.flush()
        db.session.add(User(username="shared", name="Shared", email="shared@example.test",
                            password_hash="x", role="requester", tenant_id=other.id))
        db.session.commit()
        ticket = make_ticket(20, "Cross-tenant requester", requestor_ids=["9"])
        factory = enable_rt(monkeypatch, tickets=[ticket], queues={"1": "General"},
                            users={"9": {"EmailAddress": "Shared@Example.test", "RealName": "Shared"}})
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 1, result["errors"]
        assert any("another tenant" in e for e in result["errors"])
        record = EnterpriseRecord.query.filter_by(external_id="20").one()
        assert record.requester.email.startswith("unresolved-rt-requester")


def test_a_failing_ticket_does_not_poison_the_tickets_after_it(app, monkeypatch):
    with app.app_context():
        tickets = [make_ticket(i, f"Ticket {i}", requestor_ids=["9"]) for i in (31, 32, 33)]
        factory = enable_rt(monkeypatch, tickets=tickets, queues={"1": "General"},
                            users={"9": {"EmailAddress": "dan@example.test", "RealName": "Dan"}})
        real = rt_import._create_event_record

        def flaky(rt_id, *args, **kwargs):
            if rt_id == "32":
                raise RuntimeError("database rejected this ticket")
            return real(rt_id, *args, **kwargs)

        monkeypatch.setattr(rt_import, "_create_event_record", flaky)
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 2
        assert sorted(r.external_id for r in EnterpriseRecord.query.filter_by(external_source="rt")) == ["31", "33"]


def test_import_stops_at_the_deadline_and_reports_unfinished(app, monkeypatch):
    with app.app_context():
        tickets = [make_ticket(i, f"T{i}", requestor_ids=["9"]) for i in range(40, 45)]
        factory = enable_rt(monkeypatch, tickets=tickets, queues={"1": "General"},
                            users={"9": {"EmailAddress": "eve@example.test", "RealName": "Eve"}})
        ticks = []
        result = import_from_rt(1, _admin_id(), session_factory=factory,
                                deadline=time.monotonic() - 1, tick=lambda: ticks.append(1))
        assert result["finished"] is False and result["records_created"] == 0
        assert ticks, "the heartbeat must be called"


def test_worker_runs_a_large_import_in_slices_and_completes_it(app, monkeypatch):
    with app.app_context():
        tickets = [make_ticket(i, f"T{i}", requestor_ids=["9"]) for i in range(50, 56)]
        factory = enable_rt(monkeypatch, tickets=tickets, queues={"1": "General"},
                            users={"9": {"EmailAddress": "fay@example.test", "RealName": "Fay"}})
        # Each slice ends after two tickets.
        real_import = rt_import.import_from_rt
        calls = []

        def two_per_slice(*args, **kwargs):
            calls.append(1)
            kwargs["limit"] = min(2, kwargs["limit"]) if kwargs.get("limit") is not None else 2
            kwargs["session_factory"] = factory
            result = real_import(*args, **kwargs)
            result["finished"] = result["records_created"] == 0
            return result

        monkeypatch.setattr(rt_import, "import_from_rt", two_per_slice)
        job = RTImportJob(tenant_id=1, actor_user_id=_admin_id(), search_query="id > 0", dry_run=False)
        db.session.add(job)
        db.session.commit()
        for _ in range(10):
            process_rt_import_jobs()
            db.session.expire_all()
            if db.session.get(RTImportJob, job.id).status != "Running":
                break
        job = db.session.get(RTImportJob, job.id)
        assert job.status == "Completed"
        assert json.loads(job.result_json)["records_created"] == 6
        assert EnterpriseRecord.query.filter_by(external_source="rt").count() == 6
        assert len(calls) >= 3


def test_a_preview_left_running_by_a_stopped_worker_is_marked_failed(app):
    with app.app_context():
        job = RTImportJob(tenant_id=1, actor_user_id=_admin_id(), search_query="id > 0",
                          dry_run=True, status="Running")
        db.session.add(job)
        db.session.commit()
        process_rt_import_jobs()
        db.session.expire_all()
        job = db.session.get(RTImportJob, job.id)
        assert job.status == "Failed" and "interrupted" in job.error


def test_oversized_attachment_is_noted_not_loaded(app, monkeypatch):
    monkeypatch.setattr(rt_import, "_MAX_ATTACHMENT_BYTES", 100)
    with app.app_context():
        import base64
        ticket = make_ticket(60, "Big attachment", requestor_ids=["9"])
        big = base64.b64encode(b"%PDF-" + b"x" * 500).decode()
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "gus@example.test", "RealName": "Gus"}},
            history={"60": [{"id": "600"}]},
            transactions={"600": {"Type": "Create", "Content": "see attached", "Creator": {"id": "9"}}},
            transaction_attachments={"600": [{"id": "6000"}]},
            attachment_meta={"6000": {"ContentType": "application/pdf", "Filename": "big.pdf",
                                      "ContentEncoding": "base64", "Content": big}},
        )
        result = import_from_rt(1, _admin_id(), session_factory=factory)
        assert result["records_created"] == 1
        assert result["attachments_imported"] == 0
        assert any("larger than" in e for e in result["errors"])


def test_summary_lists_stay_bounded(app, monkeypatch):
    monkeypatch.setattr(rt_import, "_MAX_SUMMARY_ITEMS", 3)
    summary = {"errors": []}
    for i in range(10):
        rt_import._note(summary, "errors", f"e{i}")
    assert len(summary["errors"]) == 4 and "omitted" in summary["errors"][-1]


@pytest.mark.parametrize("payload", [b"[1, 2, 3]", b"null", b"\"text\""])
def test_unexpected_json_shapes_are_errors_not_crashes(payload):
    class _S:
        def get(self, url, params=None, timeout=None, **kwargs):
            return FakeResponse(None, raw=payload)

    with pytest.raises(rt_import.RTResponseError):
        rt_import._get(_S(), "https://rt.example.com", "/REST/2.0/ticket/1")
