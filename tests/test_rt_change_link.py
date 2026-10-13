"""Referencing an RT ticket from a change (RT_CHANGE_LINK_ENABLED)."""
import pytest

from app import Comment, PlatformSetting, SupportGroup, Ticket, User, db, settings_cipher
from serviceops_core import rt_import, rt_link
from tests.test_app import app, client, login  # noqa: F401

RT = {
    "/REST/2.0/ticket/4321": {"id": 4321, "Subject": "Replace core switch PSU", "Status": "open",
                              "Queue": {"id": 7}, "Requestor": [{"id": 9}], "Created": "2026-10-01T09:00:00Z",
                              "CustomFields": [{"name": "Site", "values": ["Tokyo DC1"]}]},
    "/REST/2.0/queue/7": {"Name": "Network"},
    "/REST/2.0/user/9": {"EmailAddress": "kenji@example.com", "RealName": "Kenji Nakamura"},
    "/REST/2.0/ticket/4321/history": {"items": [{"id": 55}]},
    "/REST/2.0/transaction/55": {"Type": "Create", "Content": "PSU 2 failed on core-sw-01; please replace."},
}


class _Response:
    def __init__(self, path):
        self.path, self.status_code = path, 200 if path in RT else 404

    def raise_for_status(self):
        if self.status_code != 200:
            import requests
            error = requests.HTTPError(f"{self.status_code}")
            error.response = self
            raise error

    def json(self):
        return RT[self.path]


class _Session:
    def get(self, url, params=None, timeout=None):
        return _Response(url.split("rt.example", 1)[1])


@pytest.fixture()
def rt(app, monkeypatch):
    monkeypatch.setattr(rt_import, "_rt_session", lambda base_url, token: _Session())
    with app.app_context():
        tenant = User.query.filter_by(username="admin").one().tenant_id
        for key, value in (("RT_ENABLED", "true"), ("RT_BASE_URL", "https://rt.example"),
                           ("RT_CHANGE_LINK_ENABLED", "true")):
            db.session.merge(PlatformSetting(key=key, value=value, tenant_id=tenant))
        db.session.merge(PlatformSetting(key="RT_API_TOKEN", value=settings_cipher().encrypt(b"t").decode(),
                                         encrypted=True, tenant_id=tenant))
        db.session.commit()
    return app


def test_preview_summarises_the_rt_ticket_and_maps_the_queue_to_a_team(rt, client):
    login(client)
    data = client.get("/changes/rt-preview?rt_id=%234321").get_json()
    assert data["subject"] == "Replace core switch PSU" and data["queue"] == "Network"
    assert data["requestors"][0]["email"] == "kenji@example.com"
    assert data["url"] == "https://rt.example/Ticket/Display.html?id=4321"
    with rt.app_context():
        network = SupportGroup.query.filter_by(name="Network").first()
    assert data["team_id"] == (network.id if network else None)
    assert "PSU 2 failed on core-sw-01" in data["description"] and "Site: Tokyo DC1" in data["description"]
    missing = client.get("/changes/rt-preview?rt_id=99")
    assert missing.status_code == 400 and "not found" in missing.get_json()["error"]
    assert client.get("/changes/rt-preview?rt_id=abc").status_code == 400


def test_the_feature_is_off_unless_an_administrator_enables_it(rt, client):
    with rt.app_context():
        db.session.merge(PlatformSetting(key="RT_CHANGE_LINK_ENABLED", value="false",
                                         tenant_id=User.query.filter_by(username="admin").one().tenant_id))
        db.session.commit()
    login(client)
    assert client.get("/changes/rt-preview?rt_id=4321").status_code == 400
    assert 'name="rt_ticket_id"' not in client.get("/tickets/new/change").get_data(as_text=True)


def test_requesters_cannot_query_rt(rt, client):
    login(client, "employee", "Employee123!")
    assert client.get("/changes/rt-preview?rt_id=4321").status_code in (302, 403)


def test_linking_an_existing_change_adds_a_note_and_blocks_a_second_link(rt, client):
    with rt.app_context():
        admin = User.query.filter_by(username="admin").one()
        group = SupportGroup.query.filter_by(name="Network").first() or SupportGroup.query.first()
        from app import ChangeOwnership, create_ticket_with_unique_number
        first = create_ticket_with_unique_number("change", title="Switch work", description="x", priority="P3",
                                                 requester_id=admin.id)
        second = create_ticket_with_unique_number("change", title="Other work", description="x", priority="P3",
                                                  requester_id=admin.id)
        db.session.flush()
        db.session.add_all([ChangeOwnership(ticket_id=first.id, group_id=group.id),
                            ChangeOwnership(ticket_id=second.id, group_id=group.id)])
        db.session.commit()
        first_id, second_id = first.id, second.id
    login(client)
    page = client.get(f"/ticket/{first_id}").get_data(as_text=True)
    assert 'id="rt-link-form"' in page
    client.post(f"/ticket/{first_id}/rt-link", data={"rt_ticket_id": "4321"})
    with rt.app_context():
        linked = db.session.get(Ticket, first_id)
        assert (linked.external_source, linked.external_id) == ("rt", "4321")
        note = Comment.query.filter_by(ticket_id=first_id).order_by(Comment.id.desc()).first()
        assert note and "Linked RT #4321" in note.body
    assert "https://rt.example/Ticket/Display.html?id=4321" in client.get(f"/ticket/{first_id}").get_data(as_text=True)
    client.post(f"/ticket/{second_id}/rt-link", data={"rt_ticket_id": "4321"})
    with rt.app_context():
        assert db.session.get(Ticket, second_id).external_id is None
    assert rt_link.parse_rt_id(" #12 ") == "12" and rt_link.parse_rt_id("12a") is None
