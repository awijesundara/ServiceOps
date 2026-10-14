"""Project management pages, API and platform integration (B-443): every
page renders, authorization holds at the route level (including private
projects and other tenants), user input is escaped, and search, live
updates, attachments and ITSM pages respect project visibility."""
import io
import json

import pytest
from werkzeug.security import generate_password_hash

from app import (APIClient, FileAttachment, PlatformSetting, Tenant, User, create_api_token,
                 create_ticket_with_unique_number, db)
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, WorkItem
from tests.test_app import app, client, login  # noqa: F401


@pytest.fixture()
def pm(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        for name in ("dev.one", "outsider"):
            db.session.add(User(username=name, name=name.title(), email=f"{name}@test.invalid", role="agent",
                                password_hash=generate_password_hash("Passw0rd!x")))
        other = Tenant(slug="pm-web-other", name="Other")
        db.session.add(other)
        db.session.flush()
        db.session.add(User(username="other.admin", name="Other Admin", email="oa@test.invalid", role="admin",
                            password_hash=generate_password_hash("Passw0rd!x"), tenant_id=other.id))
        db.session.commit()
        manager = User.query.filter_by(username="database.manager").one()
        web = service.create_project(manager, "WEB", "Web portal", visibility="private")
        service.set_member(manager, web, User.query.filter_by(username="dev.one").one().id, "member")
        service.create_project(manager, "OPEN", "Open project", visibility="open")
        db.session.commit()
    return app


def as_user(client, username, password="Passw0rd!x"):
    client.get("/logout")
    return client.post("/login", data={"username": username, "password": password})


def test_pages_are_hidden_until_the_module_is_enabled(app, client):
    login(client)
    assert client.get("/projects").status_code == 404
    assert "All projects" not in client.get("/").get_data(as_text=True)


def test_every_page_renders_for_a_member(pm, client):
    as_user(client, "dev.one")
    assert "All projects" in client.get("/").get_data(as_text=True)
    assert client.post("/projects/WEB/items/new", data={"title": "Epic", "item_type": "epic"}).status_code == 302
    client.post("/projects/WEB/items/new", data={"title": "Story", "item_type": "story", "parent_id": "1",
                                                 "assignee_ids": [], "labels": "ui"})
    quick = client.post("/projects/WEB/items/new", data={"title": "Quick", "status_id": "2", "return": "board"})
    assert quick.headers["Location"].endswith("/projects/WEB/board")
    for path in ("/projects", "/projects/WEB/board", "/projects/WEB/board?swimlane=assignee",
                 "/projects/WEB/board?swimlane=epic", "/projects/WEB/list?group=epic&sort=priority",
                 "/projects/WEB/list?page=abc", "/work-items/WEB-2", "/work-items/web-2", "/my/work-items",
                 "/projects/WEB/items/new?parent=2", "/projects/WEB"):
        response = client.get(path)
        assert response.status_code in (200, 302), path
    assert client.get("/projects/WEB/settings").status_code == 403  # members do not administer


def test_private_projects_are_invisible_and_open_projects_read_only(pm, client):
    as_user(client, "outsider")
    assert client.get("/projects/WEB/board").status_code == 404
    assert client.get("/work-items/WEB-1").status_code == 404
    assert "WEB" not in client.get("/projects").get_data(as_text=True).split("Your projects")[1]
    assert client.get("/projects/OPEN/board").status_code == 200
    assert client.post("/projects/OPEN/items/new", data={"title": "x"}).status_code == 403
    as_user(client, "other.admin")
    assert client.get("/projects/OPEN/board").status_code == 404  # another tenant


def test_titles_and_comments_are_escaped(pm, client):
    as_user(client, "dev.one")
    client.post("/projects/WEB/items/new", data={"title": "<script>alert(1)</script>", "description": "<b>x</b>"})
    client.post("/work-items/WEB-1/comments", data={"body": "<img src=x onerror=alert(1)>"})
    for path in ("/work-items/WEB-1", "/projects/WEB/board", "/projects/WEB/list"):
        page = client.get(path).get_data(as_text=True)
        assert "<script>alert(1)" not in page and "<img src=x" not in page and "<b>x</b>" not in page


def test_board_moves_answer_json_and_refuse_readers(pm, client):
    as_user(client, "dev.one")
    client.post("/projects/WEB/items/new", data={"title": "A"})
    client.post("/projects/WEB/items/new", data={"title": "B"})
    moved = client.post("/work-items/WEB-2/move", json={"status_id": None, "before_id": None, "after_id": 1})
    assert moved.status_code == 200 and moved.get_json()["key"] == "WEB-2"
    bad = client.post("/work-items/WEB-2/move", json={"status_id": 999999})
    assert bad.status_code == 400 and "error" in bad.get_json()
    as_user(client, "outsider")
    assert client.post("/work-items/WEB-2/move", json={"status_id": 1}).status_code == 404


def test_settings_actions_for_project_administrators(pm, client):
    as_user(client, "database.manager", "Manager123!")
    with pm.app_context():
        project = Project.query.filter_by(key="WEB").one()
        statuses = [s.id for s in project.statuses]
        outsider = User.query.filter_by(username="outsider").one().id
    for data in ({"action": "details", "name": "Web portal 2", "visibility": "open", "color": "#123456"},
                 {"action": "member", "user_id": outsider, "role": "viewer"},
                 {"action": "add_status", "name": "QA", "category": "in_progress"},
                 {"action": "update_status", "status_id": statuses[0], "name": "Backlog", "category": "todo",
                  "wip_limit": "5"},
                 {"action": "move_status", "status_id": statuses[1], "direction": "up"},
                 {"action": "delete_status", "status_id": statuses[2], "replacement_id": statuses[1]},
                 {"action": "remove_member", "user_id": outsider},
                 {"action": "archive"}, {"action": "restore"}):
        assert client.post("/projects/WEB/settings", data=data).status_code == 302, data
    assert client.post("/projects/WEB/settings", data={"action": "nonsense"}).status_code == 400
    assert client.post("/projects/WEB/settings", data={"action": "update_status", "status_id": "x"}).status_code == 400
    with pm.app_context():
        project = Project.query.filter_by(key="WEB").one()
        # "In progress" moved above the renamed first status.
        assert project.name == "Web portal 2" and [s.name for s in project.statuses][:2] == ["In progress", "Backlog"]
        assert project.statuses[1].wip_limit == 5 and len(project.statuses) == 4


def test_attachments_follow_project_visibility(pm, client):
    as_user(client, "dev.one")
    client.post("/projects/WEB/items/new", data={"title": "With file"})
    upload = client.post("/work-items/WEB-1/attachments",
                         data={"file": (io.BytesIO(b"hello world"), "notes.txt")}, content_type="multipart/form-data")
    assert upload.status_code == 302
    with pm.app_context():
        attachment = FileAttachment.query.filter_by(work_item_id=WorkItem.query.one().id).one()
        attachment_id = attachment.id
    assert client.get(f"/attachments/{attachment_id}").status_code == 200
    as_user(client, "outsider")
    assert client.get(f"/attachments/{attachment_id}").status_code == 404
    as_user(client, "dev.one")
    assert client.post(f"/work-items/WEB-1/attachments/{attachment_id}/delete").status_code == 302
    with pm.app_context():
        assert FileAttachment.query.filter_by(id=attachment_id).count() == 0


def test_live_updates_are_granted_only_to_viewers(pm, client):
    as_user(client, "dev.one")
    client.post("/projects/WEB/items/new", data={"title": "Watched"})
    with pm.app_context():
        project_id = Project.query.filter_by(key="WEB").one().id
        item_id = WorkItem.query.one().id
    watch = f"project:{project_id},work_item:{item_id}"
    assert client.get(f"/events/auth?watch={watch}").get_json()["watch"] == [f"project:{project_id}",
                                                                           f"work_item:{item_id}"]
    as_user(client, "outsider")
    assert client.get(f"/events/auth?watch={watch}").get_json()["watch"] == []


def test_search_and_ticket_pages_show_only_visible_work_items(pm, client):
    as_user(client, "dev.one")
    client.post("/projects/WEB/items/new", data={"title": "Upgrade firmware on core switch"})
    with pm.app_context():
        change = create_ticket_with_unique_number("change", title="Core switch change", description="x",
                                                  priority="P3", requester_id=User.query.filter_by(username="admin").one().id)
        db.session.commit()
        change_id, change_number = change.id, change.number
    # dev.one cannot see the change (no team), so the link is refused...
    refused = client.post("/work-items/WEB-1/links", data={"link_type": "relates", "target": change_number})
    assert refused.status_code == 400
    labels = [r["label"] for r in client.get("/ui/search?q=firmware", headers={"Accept": "application/json"}).json["results"]]
    assert any(label.startswith("WEB-1") for label in labels)
    assert client.get("/ui/search?q=projects", headers={"Accept": "application/json"}).json["results"]
    login(client)  # ...the tenant administrator can link it, and the change page lists it
    assert client.post("/work-items/WEB-1/links", data={"link_type": "relates", "target": change_number}).status_code == 302
    assert "WEB-1" in client.get(f"/ticket/{change_id}").get_data(as_text=True)
    as_user(client, "outsider")
    labels = [r["label"] for r in client.get("/ui/search?q=firmware", headers={"Accept": "application/json"}).json["results"]]
    assert not any(label.startswith("WEB-1") for label in labels)


def _api(app, username, scopes):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        token, prefix, token_hash = create_api_token()
        db.session.add(APIClient(name=f"pm {username}", token_prefix=prefix, token_hash=token_hash,
                                 scopes_json=json.dumps(scopes), acting_user_id=user.id, created_by_id=user.id,
                                 tenant_id=user.tenant_id))
        db.session.commit()
    return {"Authorization": f"Bearer {token}"}


def test_api_reads_writes_and_respects_scopes_and_visibility(pm, client):
    member = _api(pm, "dev.one", ["projects:read", "projects:write"])
    reader = _api(pm, "outsider", ["projects:read"])
    assert [p["key"] for p in client.get("/api/v1/projects", headers=member).json["data"]] == ["OPEN", "WEB"]
    assert client.post("/api/v1/projects/WEB/work-items", headers=member, json={"title": "x"}).status_code == 400
    created = client.post("/api/v1/projects/WEB/work-items", headers={**member, "Idempotency-Key": "k-1"},
                          json={"title": "From API", "type": "bug", "priority": "high", "labels": ["api"]})
    assert created.status_code == 201 and created.json["data"]["key"] == "WEB-1"
    replay = client.post("/api/v1/projects/WEB/work-items", headers={**member, "Idempotency-Key": "k-1"},
                         json={"title": "From API", "type": "bug", "priority": "high", "labels": ["api"]})
    assert replay.json["data"]["key"] == "WEB-1"
    with pm.app_context():
        assert WorkItem.query.count() == 1
    assert client.post("/api/v1/projects/WEB/work-items", headers={**member, "Idempotency-Key": "k-2"},
                       json={"title": "x", "bogus": 1}).status_code == 400
    patched = client.patch("/api/v1/work-items/WEB-1", headers=member, json={"priority": "low", "story_points": 3})
    assert patched.json["data"]["priority"] == "low" and patched.json["data"]["story_points"] == 3
    assert client.post("/api/v1/work-items/WEB-1/comments", headers=member, json={"body": "hi"}).status_code == 201
    listed = client.get("/api/v1/projects/WEB/work-items?type=bug", headers=member).json
    assert [i["key"] for i in listed["data"]] == ["WEB-1"]
    assert client.get("/api/v1/work-items/WEB-1", headers=member).json["data"]["comments"][0]["body"] == "hi"
    assert client.get("/api/v1/work-items/WEB-1", headers=reader).status_code == 404  # private project
    assert client.patch("/api/v1/work-items/WEB-1", headers=reader, json={"title": "x"}).status_code == 403  # scope
    assert [p["key"] for p in client.get("/api/v1/projects", headers=reader).json["data"]] == ["OPEN"]
