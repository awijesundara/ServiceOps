"""Tests for B-121 My Workspace: personal widget layout picked from a
fixed catalog, tenant isolation, and upgrade-safety when a saved layout
references a widget_key no longer in the registry.
"""
from app import (
    Favorite, PlatformSetting, Tenant, User, UserWorkspaceLayout, db,
)
from tests.test_app import app, client, login


def test_workspace_defaults_to_a_reasonable_layout_with_no_saved_row(app, client):
    login(client)
    response = client.get("/workspace")
    assert response.status_code == 200
    assert b"Ticket counts" in response.data
    with app.app_context():
        assert UserWorkspaceLayout.query.filter_by(user_id=1).first() is None


def test_save_layout_persists_only_known_widget_keys_and_is_per_user(app, client):
    login(client)
    with app.app_context():
        db.session.add(Favorite(user_id=1, label="Test bookmark", url="/tickets"))
        db.session.commit()

    saved = client.post("/workspace", data={
        "action": "save", "widget_key": ["favorites", "not_a_real_widget"],
        "span_favorites": "2",
    })
    assert saved.status_code == 302
    with app.app_context():
        row = UserWorkspaceLayout.query.filter_by(user_id=1).one()
        assert row.layout_json == [{"widget_key": "favorites", "span": 2}]

    page = client.get("/workspace")
    assert b"Test bookmark" in page.data
    # "Ticket counts" still appears in the Customize picker's label list --
    # only its rendered widget heading should be absent when unselected.
    assert b"<h2>Ticket counts</h2>" not in page.data


def test_reset_clears_saved_layout(app, client):
    login(client)
    client.post("/workspace", data={"action": "save", "widget_key": ["favorites"], "span_favorites": "1"})
    with app.app_context():
        assert UserWorkspaceLayout.query.filter_by(user_id=1).count() == 1

    reset = client.post("/workspace", data={"action": "reset"})
    assert reset.status_code == 302
    with app.app_context():
        assert UserWorkspaceLayout.query.filter_by(user_id=1).count() == 0


def test_saved_layout_referencing_a_removed_widget_key_is_skipped_not_broken(app, client):
    """Upgrade safety: a layout saved against an older registry that later
    drops/renames a widget must not 500 or otherwise break the page."""
    login(client)
    with app.app_context():
        db.session.add(UserWorkspaceLayout(
            tenant_id=1, user_id=1,
            layout_json=[
                {"widget_key": "favorites", "span": 1},
                {"widget_key": "a_widget_that_no_longer_exists", "span": 1},
            ],
        ))
        db.session.commit()

    response = client.get("/workspace")
    assert response.status_code == 200


def test_disabled_widget_is_hidden_from_picker_and_rendering(app, client):
    login(client)
    client.post("/workspace", data={
        "action": "save", "widget_key": ["favorites", "notifications"],
        "span_favorites": "1", "span_notifications": "1",
    })
    with app.app_context():
        db.session.add(PlatformSetting(
            key="WORKSPACE_WIDGET_NOTIFICATIONS_ENABLED", value="false", tenant_id=1, encrypted=False,
        ))
        db.session.commit()

    page = client.get("/workspace")
    assert b"name=\"widget_key\" value=\"notifications\"" not in page.data
    with app.app_context():
        row = UserWorkspaceLayout.query.filter_by(user_id=1).one()
        # The saved layout still remembers the choice -- it's the current
        # render/picker that hides it, not a silent data loss.
        assert any(item["widget_key"] == "notifications" for item in row.layout_json)


def test_workspace_layout_is_tenant_and_user_isolated(app, client):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="workspace-other", name="Other Tenant"))
        other_user = User(
            username="other.workspace.user", name="Other Workspace User",
            email="other.workspace.user@test.invalid", password_hash="x",
            role="requester", tenant_id=2,
        )
        db.session.add(other_user)
        db.session.flush()
        db.session.add(UserWorkspaceLayout(
            tenant_id=2, user_id=other_user.id,
            layout_json=[{"widget_key": "favorites", "span": 1}],
        ))
        db.session.commit()
        other_user_id = other_user.id

    login(client)
    client.post("/workspace", data={"action": "save", "widget_key": ["ticket_stats"], "span_ticket_stats": "2"})
    with app.app_context():
        admin_row = UserWorkspaceLayout.query.filter_by(user_id=1).one()
        other_row = UserWorkspaceLayout.query.filter_by(user_id=other_user_id).one()
        assert admin_row.id != other_row.id
        assert admin_row.layout_json != other_row.layout_json
