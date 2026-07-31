"""Tests for the Request Tracker (RT) ticket import (serviceops_core/rt_import.py).

These mock RT entirely (no live RT instance required) by passing a fake
session factory into import_from_rt, matching the same network-mocking
approach used by tests/test_netbox_sync.py.
"""
import os
import tempfile

import pytest

from app import (
    ChangeGovernance, ChangeOwnership, EnterpriseRecord, PlatformSetting,
    SupportGroup, Ticket, User, create_app, db,
)
from serviceops_core.rt_import import RTImportError, import_from_rt


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}"})
    with app.app_context():
        db.session.commit()
    yield app
    os.unlink(path)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeRTSession:
    def __init__(self, tickets, queues, users, history=None, transactions=None,
                 transaction_attachments=None, attachment_meta=None):
        self.tickets = {str(t["id"]): t for t in tickets}
        self.queues = queues
        self.users = users
        self.history = history or {}
        self.transactions = transactions or {}
        self.transaction_attachments = transaction_attachments or {}
        self.attachment_meta = attachment_meta or {}

    def get(self, url, params=None, timeout=None):
        if url.endswith("/REST/2.0/tickets"):
            items = [{"id": t_id} for t_id in self.tickets]
            return FakeResponse({"items": items, "page": 1, "pages": 1})
        for t_id, ticket in self.tickets.items():
            if url.endswith(f"/REST/2.0/ticket/{t_id}"):
                return FakeResponse(ticket)
            if url.endswith(f"/REST/2.0/ticket/{t_id}/history"):
                return FakeResponse({"items": self.history.get(t_id, [])})
        for queue_id, name in self.queues.items():
            if url.endswith(f"/REST/2.0/queue/{queue_id}"):
                return FakeResponse({"Name": name})
        for user_id, contact in self.users.items():
            if url.endswith(f"/REST/2.0/user/{user_id}"):
                return FakeResponse(contact)
        for txn_id, items in self.transaction_attachments.items():
            if url.endswith(f"/REST/2.0/transaction/{txn_id}/attachments"):
                return FakeResponse({"items": items})
        for txn_id, txn in self.transactions.items():
            if url.endswith(f"/REST/2.0/transaction/{txn_id}"):
                return FakeResponse(txn)
        for att_id, meta in self.attachment_meta.items():
            if url.endswith(f"/REST/2.0/attachment/{att_id}"):
                return FakeResponse(meta)
        return FakeResponse({"items": []})

    def close(self):
        pass


def enable_rt(monkeypatch, **session_kwargs):
    for key, value in (
        ("RT_ENABLED", "true"),
        ("RT_BASE_URL", "https://rt.example.com"),
        ("RT_API_TOKEN", "test-token"),
    ):
        existing = db.session.get(PlatformSetting, key)
        if existing:
            existing.value = value
        else:
            db.session.add(PlatformSetting(key=key, value=value, encrypted=False))
    db.session.commit()

    import app as core_app
    monkeypatch.setattr(core_app, "integration_endpoint_resolves_safely", lambda url, **kwargs: True)

    def factory(base_url, token):
        return FakeRTSession(**session_kwargs)
    return factory


def make_ticket(id_, subject, status="open", priority="80", queue_id="1", owner_id=None, requestor_ids=None):
    return {
        "id": id_, "Subject": subject, "Status": status, "Priority": priority,
        "Queue": {"id": queue_id, "type": "queue"},
        "Owner": {"id": owner_id, "type": "user"} if owner_id else None,
        "Requestor": [{"id": r, "type": "user"} for r in (requestor_ids or [])],
        "Created": "2024-01-15T10:30:00Z",
    }


def test_creates_new_it_operations_event_from_rt_ticket(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(101, "Printer is broken", queue_id="5", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket],
            queues={"5": "Help Desk"},
            users={"9": {"EmailAddress": "alice@example.test", "RealName": "Alice"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert result["records_created"] == 1
        assert result["teams_created"] == 1
        assert result["users_created"] == 1

        record = EnterpriseRecord.query.filter_by(external_source="rt", external_id="101").one()
        assert record.title == "Printer is broken"
        assert record.domain == "event"
        assert record.record_type == "RT Ticket"
        assert record.state == "In Progress"
        assert record.priority == "P1"
        assert record.requester.email == "alice@example.test"
        assert record.support_group.name == "Help Desk"


def test_rerun_skips_already_imported_ticket(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(202, "Duplicate check", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "bob@example.test", "RealName": "Bob"}},
        )
        first = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert first["records_created"] == 1
        second = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert second["records_created"] == 0
        assert second["already_imported"] == 1
        assert EnterpriseRecord.query.filter_by(external_source="rt", external_id="202").count() == 1


def test_dry_run_does_not_commit(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(303, "Preview only", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "carol@example.test", "RealName": "Carol"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, dry_run=True, session_factory=factory)
        assert result["dry_run"] is True
        assert result["records_created"] == 1
        assert len(result["preview"]) == 1
        assert EnterpriseRecord.query.filter_by(domain="event", record_type="RT Ticket").count() == 0
        assert User.query.filter_by(email="carol@example.test").count() == 0


def test_correspondence_folded_into_description(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(404, "With history", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "dan@example.test", "RealName": "Dan"}},
            history={"404": [{"id": "77"}]},
            transactions={"77": {"Type": "Correspond", "Content": "Initial message body", "Creator": {"id": "9"}}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert result["comments_imported"] == 1
        record = EnterpriseRecord.query.filter_by(external_source="rt", external_id="404").one()
        assert "Initial message body" in record.description
        assert "Dan" in record.description


def test_correspondence_falls_back_to_attachment_body_and_notes_status_changes(app, monkeypatch):
    """Reproduces the real-world case: a Correspond transaction with no
    inline Content (its body lives in an attachment instead), a
    file-only Correspond transaction (no text body at all, just a
    spreadsheet), and a Status transaction -- all of RT's history, not
    just the first message, must show up in the imported description."""
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(606, "Full history", status="closed", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={
                "9": {"EmailAddress": "dan@example.test", "RealName": "Dan"},
                "10": {"EmailAddress": "robert@example.test", "RealName": "Robert Murray"},
            },
            history={"606": [{"id": "77"}, {"id": "78"}, {"id": "79"}]},
            transactions={
                "77": {"Type": "Create", "Content": "Original request text", "Creator": {"id": "9"}},
                "78": {"Type": "Correspond", "Content": "", "Creator": {"id": "10"}},
                "79": {"Type": "Status", "OldValue": "new", "NewValue": "closed", "Creator": {"id": "10"}},
            },
            transaction_attachments={"78": [{"id": "501"}]},
            attachment_meta={"501": {
                "Filename": "form.xlsx",
                "ContentType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "Content": "",
            }},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        record = EnterpriseRecord.query.filter_by(external_source="rt", external_id="606").one()
        assert "Original request text" in record.description
        assert "form.xlsx" in record.description
        assert "Status changed from 'new' to 'closed'" in record.description
        assert record.state == "Closed"
        assert result["comments_imported"] == 2


def test_unrecognized_status_reports_error_instead_of_silently_defaulting(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(707, "Weird status", status="triaging", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "gail@example.test", "RealName": "Gail"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        record = EnterpriseRecord.query.filter_by(external_source="rt", external_id="707").one()
        assert record.state == "New"
        assert any("Unrecognized RT status" in error for error in result["errors"])


def test_rt_import_disabled_raises(app):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        with pytest.raises(RTImportError):
            import_from_rt(1, actor_user_id=admin_id)


def test_unmatched_queue_reuses_existing_support_group_by_name(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        db.session.add(SupportGroup(name="Field Services", tenant_id=1))
        db.session.commit()
        ticket = make_ticket(505, "Reuse existing team", queue_id="3", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"3": "Field Services"},
            users={"9": {"EmailAddress": "erin@example.test", "RealName": "Erin"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert result["teams_created"] == 0
        assert SupportGroup.query.filter_by(name="Field Services").count() == 1


def test_cr_tagged_subject_imports_as_change_not_event(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(808, "[CR] Upgrade core switch firmware", status="resolved", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "Network"},
            users={"9": {"EmailAddress": "frank@example.test", "RealName": "Frank"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert result["changes_created"] == 1
        assert result["events_created"] == 0
        assert EnterpriseRecord.query.filter_by(external_source="rt", external_id="808").count() == 0

        change = Ticket.query.filter_by(external_source="rt", external_id="808").one()
        assert change.kind == "change"
        assert change.title == "[CR] Upgrade core switch firmware"
        assert change.state == "Resolved"
        governance = ChangeGovernance.query.filter_by(ticket_id=change.id).one()
        assert governance.ccb_required is False
        ownership = ChangeOwnership.query.filter_by(ticket_id=change.id).one()
        assert ownership.group.name == "Network"


def test_cr_tag_is_case_insensitive_and_checked_anywhere_in_subject(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(809, "Firewall rule update [cr] batch 3", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "gina@example.test", "RealName": "Gina"}},
        )
        result = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert result["changes_created"] == 1


def test_change_rejected_status_maps_to_cancelled_not_rejected(app, monkeypatch):
    """Ticket.state uses "Cancelled", not "Rejected" (that's an
    EnterpriseRecord-only state) -- the change-target status map must
    differ from the event-target one."""
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(810, "[CR] Abandoned change", status="rejected", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "hank@example.test", "RealName": "Hank"}},
        )
        import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        change = Ticket.query.filter_by(external_source="rt", external_id="810").one()
        assert change.state == "Cancelled"


def test_already_imported_change_is_not_reimported_as_event(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = make_ticket(811, "[CR] Idempotency check", requestor_ids=["9"])
        factory = enable_rt(
            monkeypatch, tickets=[ticket], queues={"1": "General"},
            users={"9": {"EmailAddress": "iris@example.test", "RealName": "Iris"}},
        )
        first = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert first["changes_created"] == 1
        second = import_from_rt(1, actor_user_id=admin_id, session_factory=factory)
        assert second["already_imported"] == 1
        assert second["records_created"] == 0
        assert Ticket.query.filter_by(external_source="rt", external_id="811").count() == 1
