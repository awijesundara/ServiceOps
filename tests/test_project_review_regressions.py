"""2026-10-16 review: API privacy, membership invariants, estimates and moved keys."""
import pytest
from werkzeug.exceptions import HTTPException

from app import User, db
from serviceops_core.projects import operations, service
from serviceops_core.projects.models import Project, ProjectMember
from tests.test_app import app, client, login  # noqa: F401
from tests.test_projects_web import pm, _api  # noqa: F401


@pytest.mark.parametrize("visibility,username,role,allowed", [
    ("admin", "dev.one", "member", False),
    ("member", "outsider", "viewer", False),
    ("member", "outsider", None, False),
    ("admin", "database.manager", "admin", True),
    ("member", "dev.one", "member", True),
    (None, "outsider", None, True),
])
def test_api_comment_visibility_matches_web_policy(pm, client, visibility, username, role, allowed):
    with pm.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        project = Project.query.filter_by(key="WEB").one()
        project.visibility = "open"
        if role == "viewer":
            service.set_member(manager, project, User.query.filter_by(username=username).one().id, role)
        item = service.create_item(manager, project, "Privacy probe")
        service.add_comment(manager, item, "Restricted review comment", visibility=visibility)
        db.session.commit()
        viewer = User.query.filter_by(username=username).one()
        assert bool(service.visible_comments(viewer, item)) is allowed
    response = client.get("/api/v1/work-items/WEB-1", headers=_api(pm, username, ["projects:read"]))
    assert response.status_code == 200
    assert ("Restricted review comment" in response.get_data(as_text=True)) is allowed


@pytest.mark.parametrize("role", ["member", "viewer"])
def test_last_project_administrator_cannot_be_demoted(pm, role):
    with pm.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        project = Project.query.filter_by(key="WEB").one()
        with pytest.raises(HTTPException) as error:
            service.set_member(manager, project, manager.id, role)
        assert error.value.code == 409
        db.session.rollback()
        assert ProjectMember.query.filter_by(project_id=project.id, role="admin").count() == 1
        developer = User.query.filter_by(username="dev.one").one()
        service.set_member(manager, project, developer.id, "admin")
        service.set_member(manager, project, manager.id, role)
        db.session.commit()
        assert service.project_role(developer, project) == "admin"
        assert service.project_role(manager, project) == role


@pytest.mark.parametrize("remaining,expected", [(None, 120), (0, 0), (30, 30), (150, 150)])
def test_api_creation_preserves_explicit_remaining_estimate(pm, client, remaining, expected):
    headers = {**_api(pm, "dev.one", ["projects:read", "projects:write"]), "Idempotency-Key": "remaining"}
    body = {"title": "Estimate probe", "estimate_minutes": 120}
    if remaining is not None:
        body["remaining_minutes"] = remaining
    response = client.post("/api/v1/projects/WEB/work-items", headers=headers, json=body)
    assert response.status_code == 201, response.json
    assert response.json["data"]["remaining_minutes"] == expected
    assert client.post("/api/v1/projects/WEB/work-items", headers=headers, json=body).json == response.json


@pytest.mark.parametrize("remaining", [-1, 10000001, "not a number", True, {}])
def test_api_creation_refuses_invalid_remaining_estimates(pm, client, remaining):
    headers = {**_api(pm, "dev.one", ["projects:write"]), "Idempotency-Key": "bad-remaining"}
    response = client.post("/api/v1/projects/WEB/work-items", headers=headers,
                           json={"title": "Invalid estimate", "remaining_minutes": remaining})
    assert response.status_code == 400
    with pm.app_context():
        assert service.WorkItem.query.filter_by(title="Invalid estimate").count() == 0


def test_moved_keys_work_for_reads_writes_and_respect_destination_access(pm, client):
    with pm.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        developer = User.query.filter_by(username="dev.one").one()
        source = Project.query.filter_by(key="WEB").one()
        target = Project.query.filter_by(key="OPEN").one()
        target.visibility = "private"
        service.set_member(manager, target, developer.id, "member")
        item = service.create_item(manager, source, "Move probe")
        operations.move_item(manager, item, target)
        db.session.commit()
    headers = _api(pm, "dev.one", ["projects:read", "projects:write"])
    response = client.get("/api/v1/work-items/WEB-1", headers=headers)
    assert response.status_code == 200 and response.json["data"]["key"] == "OPEN-1"
    response = client.patch("/api/v1/work-items/WEB-1", headers=headers, json={"title": "Updated via old key"})
    assert response.status_code == 200 and response.json["data"]["title"] == "Updated via old key"
    assert client.post("/api/v1/work-items/WEB-1/comments", headers=headers, json={"body": "Via alias"}).status_code == 201
    with pm.app_context():
        manager = User.query.filter_by(username="database.manager").one()
        developer = User.query.filter_by(username="dev.one").one()
        target = Project.query.filter_by(key="OPEN").one()
        service.remove_member(manager, target, developer.id)
        db.session.commit()
    for path in ("WEB-1", "OPEN-1"):
        assert client.get(f"/api/v1/work-items/{path}", headers=headers).status_code == 404
        assert client.patch(f"/api/v1/work-items/{path}", headers=headers, json={"title": "Forbidden"}).status_code == 404
        assert client.post(f"/api/v1/work-items/{path}/comments", headers=headers, json={"body": "Forbidden"}).status_code == 404
