"""Typed hostile inputs must fail atomically as client errors, never 500s."""
import pytest

from app import db
from serviceops_core.projects.models import WorkItem
from tests.test_app import app, client, login  # noqa: F401
from tests.test_projects_web import _api, pm  # noqa: F401


@pytest.mark.parametrize("field,value", [
    ("title", 42), ("description", 42), ("environment", 42), ("parent_key", 42),
    ("labels", {"unexpected": "object"}), ("labels", [True]), ("labels", [42]),
    ("estimate_minutes", float("inf")), ("remaining_minutes", float("inf")),
    ("estimate_minutes", 1.5), ("component_ids", [float("inf")]),
    ("assignee_ids", [float("inf")]), ("assignee_ids", [True]),
    ("status_id", float("inf")), ("status_id", 1.5),
])
def test_project_api_rejects_wrong_types_without_partial_writes(pm, client, field, value):
    headers = {**_api(pm, "dev.one", ["projects:write"]), "Idempotency-Key": "invalid-input"}
    response = client.post("/api/v1/projects/WEB/work-items", headers=headers, json={"title": "Safe", field: value})
    assert response.status_code == 400, (field, response.status_code)
    with pm.app_context():
        assert WorkItem.query.count() == 0
        db.session.rollback()


@pytest.mark.parametrize("payload", [["unexpected"], "unexpected", 42, True])
def test_project_json_ui_endpoints_reject_non_objects(pm, client, payload):
    login(client, "dev.one", "Passw0rd!x")
    with pm.app_context():
        from app import User
        from serviceops_core.projects import service
        from serviceops_core.projects.models import Project
        user = User.query.filter_by(username="dev.one").one()
        project = Project.query.filter_by(key="WEB").one()
        item_key = service.create_item(user, project, "Safe").key
        db.session.commit()
    for url in ("/projects/markdown-preview", f"/work-items/{item_key}/move"):
        assert client.post(url, json=payload).status_code == 400, url
