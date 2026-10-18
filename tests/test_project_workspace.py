"""Context navigation respects the existing project and tenant permissions."""
import pytest

from tests.test_app import app, client, login  # noqa: F401
from tests.test_projects_phase2 import pm, project, u  # noqa: F401
from serviceops_core.projects import service
from serviceops_models import db


@pytest.mark.parametrize("username,settings_visible", [("admin", True), ("dev.one", False), ("viewer.one", False)])
def test_context_navigation_only_exposes_permitted_project_actions(pm, client, username, settings_visible):
    row = project()
    service.create_project(u("admin"), "SECRET", "Private project not shared with members")
    db.session.commit()
    login(client, username, "Admin123!" if username == "admin" else "Passw0rd!x")
    response = client.get(f"/projects/{row.key}/board")
    assert response.status_code == 200
    assert b'aria-label="Current project navigation"' in response.data
    assert b'href="/projects/WEB/backlog"' in response.data
    assert (b'href="/projects/WEB/settings"' in response.data) is settings_visible
    assert b"Private project not shared with members" not in response.data
    if username != "admin":
        assert client.get("/projects/SECRET/board").status_code == 404
        assert client.get("/projects/WEB/settings").status_code == 403
