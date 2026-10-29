"""Preference saves retain their category without accepting arbitrary targets."""
import pytest
from html.parser import HTMLParser

from app import CiClassPermission, ConfigurationItem, db
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize("category,fragment", [("general", ""), ("lists", "#lists"), ("forms", "#forms"),
                                               ("https://other.invalid", ""), ("notifications", "")])
def test_display_save_returns_to_allowed_category(client, category, fragment):
    login(client)
    response = client.post("/preferences", data={"preference_category": category, "font_scale": "120"})
    assert response.status_code == 302
    assert response.location == "/preferences" + fragment


def test_notification_save_returns_to_notifications(client):
    login(client)
    response = client.post("/preferences", data={"action": "notifications"})
    assert response.status_code == 302
    assert response.location == "/preferences#notifications"


class Inputs(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and "name" in values:
            self.fields[values["name"]] = values


def test_ci_permission_editor_does_not_preselect_denied_updates(client, app):
    login(client)
    with app.app_context():
        db.session.add(ConfigurationItem(name="Permission UI test", ci_class="Server", tenant_id=1))
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Server", role="agent",
                                        can_read=True, can_create=False, can_update=False, can_delete=False))
        db.session.add(CiClassPermission(tenant_id=1, ci_class="Server", role="admin",
                                        can_read=True, can_create=True, can_update=True, can_delete=True))
        db.session.commit()
    parser = Inputs()
    parser.feed(client.get("/cmdb/permissions").get_data(as_text=True))
    assert "checked" not in parser.fields["update__Server__agent"]
    assert "checked" not in parser.fields["update__Server__manager"]
    assert "checked" in parser.fields["read__Server__agent"]
    # Submitting the displayed values must preserve the denied permissions.
    payload = {name: "on" for name, attrs in parser.fields.items() if "checked" in attrs}
    payload["ci_class"] = "Server"
    assert client.post("/cmdb/permissions", data=payload).status_code == 302
    with app.app_context():
        assert not CiClassPermission.query.filter_by(tenant_id=1, ci_class="Server", role="agent").one().can_update
        admin = CiClassPermission.query.filter_by(tenant_id=1, ci_class="Server", role="admin").one()
        assert admin.can_read and admin.can_create and admin.can_update and admin.can_delete
