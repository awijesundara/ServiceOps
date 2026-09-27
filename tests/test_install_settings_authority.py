"""Install-wide PlatformSetting rows: a tenant administrator owns them while
the installation has one tenant; with a second tenant only a platform
administrator (superadmin) may change them."""
from werkzeug.security import generate_password_hash

from app import PlatformSetting, Tenant, User, UserRoleGrant, db, setting_value
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)

PROXY_FORM = {"OUTBOUND_PROXY_URL": "http://proxy.internal:3128", "SMTP_PROXY_MODE": "none"}


def add_second_tenant(app):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="settings-other", name="Other organisation"))
        db.session.commit()


def add_superadmin(app):
    with app.app_context():
        user = User(username="platform.owner", name="Platform Owner", email="po@test.invalid",
                    password_hash=generate_password_hash("PlatformOwner123!"), role="superadmin")
        db.session.add(user)
        db.session.flush()
        db.session.add(UserRoleGrant(user_id=user.id, role="superadmin"))
        db.session.commit()


def test_single_tenant_admin_can_change_install_settings(client, app):
    login(client)
    assert client.post("/admin/settings/outbound_network", data=PROXY_FORM).status_code in (200, 302)
    with app.app_context():
        assert setting_value("OUTBOUND_PROXY_URL", "") == PROXY_FORM["OUTBOUND_PROXY_URL"]


def test_tenant_admin_cannot_change_install_settings_once_there_is_a_second_tenant(client, app):
    add_second_tenant(app)
    login(client)
    assert client.get("/admin/settings/outbound_network").status_code == 200
    refused = client.post("/admin/settings/outbound_network", data=PROXY_FORM)
    assert refused.status_code == 403
    assert b"platform administrator" in refused.data
    for data in ({"action": "set_ticket_defaults", "default_ticket_priority": "P2"},
                 {"action": "set_change_approval_policy", "ccb_required_environments": "Production"}):
        assert client.post("/itil/administration", data=data).status_code == 403
    with app.app_context():
        assert db.session.get(PlatformSetting, "OUTBOUND_PROXY_URL") is None
        assert db.session.get(PlatformSetting, "DEFAULT_TICKET_PRIORITY") is None


def test_superadmin_can_change_install_settings_with_several_tenants(client, app):
    add_second_tenant(app)
    add_superadmin(app)
    login(client, "platform.owner", "PlatformOwner123!")
    assert client.post("/admin/settings/outbound_network", data=PROXY_FORM).status_code in (200, 302)
    with app.app_context():
        assert setting_value("OUTBOUND_PROXY_URL", "") == PROXY_FORM["OUTBOUND_PROXY_URL"]
