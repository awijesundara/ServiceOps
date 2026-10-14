"""Project management phase 2 (B-449): Jira's work item completeness.
Resolutions, components, versions, time tracking, votes, stars, comment
visibility and reactions, clone, move, convert, bulk change, link types,
Markdown, Your work and the API additions; with negative authorization
and tenant cases."""
import io
import json

import pytest
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from app import (APIClient, FileAttachment, Notification, PlatformSetting, Tenant, User, create_api_token, db)
from serviceops_core.projects import catalog, markdown, operations, releases, service, tracking
from serviceops_core.projects.models import (WorkItem, WorkItemKeyAlias, WorkItemLink, WorkItemWorklog)
from tests.test_app import app, client, login  # noqa: F401


def _user(username, role="agent", tenant_id=None):
    user = User(username=username, name=username.replace(".", " ").title(), email=f"{username}@test.invalid",
                role=role, password_hash=generate_password_hash("Passw0rd!x"))
    if tenant_id:
        user.tenant_id = tenant_id
    db.session.add(user)
    db.session.flush()
    return user


@pytest.fixture()
def pm(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        for name in ("dev.one", "dev.two", "viewer.one", "outsider"):
            _user(name)
        other = Tenant(slug="pm2-other", name="Other")
        db.session.add(other)
        db.session.flush()
        _user("other.admin", role="admin", tenant_id=other.id)
        db.session.commit()
    with app.app_context():
        yield app


def u(username):
    return User.query.filter_by(username=username).one()


def expect_abort(code, fn, *args, **kwargs):
    with pytest.raises(HTTPException) as error:
        fn(*args, **kwargs)
    assert error.value.code == code, error.value.description
    db.session.rollback()


def project(key="WEB", visibility="private"):
    manager = u("database.manager")
    row = service.create_project(manager, key, f"{key} project", visibility=visibility)
    service.set_member(manager, row, u("dev.one").id, "member")
    service.set_member(manager, row, u("dev.two").id, "member")
    service.set_member(manager, row, u("viewer.one").id, "viewer")
    db.session.commit()
    return row


def status(row, category):
    return next(s for s in row.statuses if s.category == category)


# --- durations and time tracking ------------------------------------------------------

def test_durations_follow_the_working_day_and_week(pm):
    assert tracking.parse_duration("1w 2d 3h 30m") == (5 * 8 + 2 * 8 + 3) * 60 + 30
    assert tracking.parse_duration("1.5h") == 90 and tracking.parse_duration("2") == 120
    assert tracking.parse_duration("") is None
    assert tracking.format_duration(tracking.parse_duration("1w 2d 3h 30m")) == "1w 2d 3h 30m"
    assert tracking.format_duration(0) == "0m"
    expect_abort(400, tracking.parse_duration, "soon")
    db.session.merge(PlatformSetting(key="PROJECTS_HOURS_PER_DAY", value="6", tenant_id=u("admin").tenant_id))
    db.session.commit()
    assert tracking.parse_duration("1d") == 360


def test_work_logs_adjust_remaining_and_only_authors_or_admins_change_them(pm):
    web = project()
    item = service.create_item(u("dev.one"), web, "Build", estimate_minutes=480)
    db.session.commit()
    assert item.remaining_minutes == 480
    tracking.log_work(u("dev.one"), item, "2h")
    assert (item.spent_minutes, item.remaining_minutes) == (120, 360)
    tracking.log_work(u("dev.one"), item, "1h", remaining_mode="leave")
    assert (item.spent_minutes, item.remaining_minutes) == (180, 360)
    tracking.log_work(u("dev.two"), item, "30m", remaining_mode="new", new_remaining="1h")
    assert item.remaining_minutes == 60
    tracking.log_work(u("dev.two"), item, "15m", remaining_mode="reduce", reduce_by="45m")
    assert item.remaining_minutes == 15
    db.session.commit()
    first = WorkItemWorklog.query.filter_by(work_item_id=item.id, author_id=u("dev.one").id).first()
    expect_abort(403, tracking.delete_worklog, u("dev.two"), item, first)
    expect_abort(403, tracking.log_work, u("viewer.one"), item, "1h")
    expect_abort(400, tracking.log_work, u("dev.one"), item, "0m")
    tracking.delete_worklog(u("database.manager"), item, first)  # project administrator
    db.session.commit()
    assert item.spent_minutes == 60 + 30 + 15  # the 2h log by dev.one was deleted


# --- resolutions, components, versions --------------------------------------------------------

def test_resolution_is_set_on_done_and_cleared_on_reopen(pm):
    web = project()
    item = service.create_item(u("dev.one"), web, "Fix")
    service.update_item(u("dev.one"), item, {"status_id": status(web, "done").id})
    assert item.resolution.name == "Done" and item.resolved_at
    wont = next(r for r in catalog.resolutions(item.tenant_id) if r.name == "Won't do")
    service.update_item(u("dev.one"), item, {"resolution_id": wont.id})
    assert item.resolution.name == "Won't do"
    service.update_item(u("dev.one"), item, {"status_id": status(web, "todo").id})
    assert item.resolution is None and item.resolved_at is None
    born_done = service.create_item(u("dev.one"), web, "Already done", status_id=status(web, "done").id)
    assert born_done.resolution.name == "Done"
    other_tenant_resolution = catalog.resolutions(u("other.admin").tenant_id)[0]
    service.update_item(u("dev.one"), born_done, {"status_id": status(web, "done").id})
    expect_abort(400, service.update_item, u("dev.one"), born_done, {"resolution_id": other_tenant_resolution.id})


def test_components_choose_the_default_assignee(pm):
    web = project()
    manager = u("database.manager")
    led = releases.save_component(manager, web, "Frontend", lead_id=u("dev.two").id, default_assignee="component_lead")
    plain = releases.save_component(manager, web, "Docs")
    db.session.commit()
    item = service.create_item(u("dev.one"), web, "Button", component_ids=[led.id])
    assert [a.username for a in item.assignees] == ["dev.two"]
    assert service.create_item(u("dev.one"), web, "Copy", component_ids=[plain.id]).assignees == []
    service.update_project(manager, web, default_assignee="project_lead")
    assert [a.username for a in service.create_item(u("dev.one"), web, "Lead's").assignees] == ["database.manager"]
    assert service.create_item(u("dev.one"), web, "Chosen", assignee_ids=[]).assignees == []  # explicit choice wins
    expect_abort(409, releases.save_component, manager, web, "frontend")
    expect_abort(403, releases.save_component, u("dev.one"), web, "Mine")
    expect_abort(400, releases.save_component, manager, web, "No lead", default_assignee="component_lead")
    other = project("OTH")
    expect_abort(400, service.create_item, u("dev.one"), other, "Cross", component_ids=[led.id])


def test_versions_release_merge_and_delete(pm):
    web = project()
    manager = u("database.manager")
    v1 = releases.save_version(manager, web, "1.0", release_date="2026-11-01")
    v2 = releases.save_version(manager, web, "1.1")
    db.session.commit()
    done_item = service.create_item(u("dev.one"), web, "Shipped", fix_version_ids=[v1.id])
    open_item = service.create_item(u("dev.one"), web, "Late", fix_version_ids=[v1.id], affects_version_ids=[v1.id])
    service.update_item(u("dev.one"), done_item, {"status_id": status(web, "done").id})
    db.session.commit()
    assert releases.version_progress(v1) == {"total": 2, "done": 1, "in_progress": 0, "todo": 1}
    assert releases.release_version(manager, web, v1, move_to=v2) == 1
    db.session.commit()
    db.session.expire_all()
    assert v1.released and [v.name for v in open_item.fix_versions] == ["1.1"]
    assert [v.name for v in done_item.fix_versions] == ["1.0"]
    expect_abort(409, releases.release_version, manager, web, v1)
    expect_abort(403, releases.release_version, u("dev.one"), web, v2)
    releases.merge_versions(manager, web, v2, v1)
    db.session.commit()
    db.session.expire_all()
    assert [v.name for v in open_item.fix_versions] == ["1.0"] and len(releases.versions(web)) == 1
    v3 = releases.save_version(manager, web, "2.0")
    releases.delete_version(manager, web, v1, fix_target=v3)
    db.session.commit()
    db.session.expire_all()
    assert [v.name for v in open_item.fix_versions] == ["2.0"] and open_item.affects_versions == []
    expect_abort(400, releases.save_version, manager, web, "bad", start_date="2026-12-01", release_date="2026-11-01")


# --- votes, stars, views ----------------------------------------------------------------------------

def test_votes_stars_and_views(pm):
    web = project()
    item = service.create_item(u("dev.one"), web, "Idea")
    db.session.commit()
    expect_abort(409, service.toggle_vote, u("dev.one"), item)  # own report
    assert service.toggle_vote(u("dev.two"), item) is True and len(service.voters(item)) == 1
    assert service.toggle_vote(u("dev.two"), item) is False
    service.update_item(u("dev.one"), item, {"status_id": status(web, "done").id})
    expect_abort(409, service.toggle_vote, u("viewer.one"), item)  # resolved
    expect_abort(404, service.toggle_vote, u("outsider"), item)  # cannot see the project
    assert service.toggle_star(u("viewer.one"), "work_item", item) is True
    assert service.is_starred(u("viewer.one"), "work_item", item.id)
    expect_abort(404, service.toggle_star, u("outsider"), "project", web)
    service.record_view(u("viewer.one"), item)
    service.record_view(u("viewer.one"), item)
    db.session.commit()


# --- comments --------------------------------------------------------------------------------------

def test_restricted_comments_are_hidden_and_only_notify_allowed_people(pm):
    web = project()
    item = service.create_item(u("dev.one"), web, "Secret plan")
    service.set_watching(u("viewer.one"), item, True)
    service.set_watching(u("dev.two"), item, True)
    db.session.commit()
    comment = service.add_comment(u("dev.one"), item, "Members only @viewer.one", visibility="member")
    db.session.commit()
    assert comment not in service.visible_comments(u("viewer.one"), item)
    assert comment in service.visible_comments(u("dev.two"), item)
    assert Notification.query.filter_by(user_id=u("viewer.one").id).count() == 0
    assert Notification.query.filter_by(user_id=u("dev.two").id).count() == 1
    expect_abort(404, service.comment_or_404, u("viewer.one"), item, comment.id)
    expect_abort(403, service.add_comment, u("dev.one"), item, "admins", visibility="admin")  # not an admin
    expect_abort(400, service.add_comment, u("dev.one"), item, "x", visibility="everyone")


def test_comment_edit_delete_and_reactions(pm):
    web = project("OPEN", visibility="open")
    item = service.create_item(u("dev.one"), web, "Discuss")
    comment = service.add_comment(u("dev.one"), item, "First")
    db.session.commit()
    expect_abort(403, service.edit_comment, u("dev.two"), item, comment, "Hijack")
    service.edit_comment(u("dev.one"), item, comment, "First, edited")
    assert comment.edited_at and comment.body == "First, edited"
    assert service.toggle_reaction(u("outsider"), item, comment, "👍") is True  # readers may react
    assert service.toggle_reaction(u("dev.two"), item, comment, "👍") is True
    assert service.reactions_for([comment.id], u("dev.two"))[comment.id] == [("👍", 2, True)]
    assert service.toggle_reaction(u("dev.two"), item, comment, "👍") is False
    expect_abort(400, service.toggle_reaction, u("dev.two"), item, comment, "<script>")
    expect_abort(403, service.delete_comment, u("dev.two"), item, comment)
    service.delete_comment(u("database.manager"), item, comment)
    db.session.commit()
    assert service.visible_comments(u("dev.one"), item) == []


# --- clone, move, convert, bulk --------------------------------------------------------------------

def test_clone_copies_fields_subtasks_links_and_separate_attachment_files(pm):
    web = project()
    story = service.create_item(u("dev.one"), web, "Story", item_type="story", labels="ui", story_points=3)
    sub = service.create_item(u("dev.one"), web, "Sub", item_type="subtask", parent_id=story.id)
    other = service.create_item(u("dev.one"), web, "Other")
    service.add_link(u("dev.one"), story, "blocks", other.key)
    db.session.commit()
    storage = __import__("app").current_storage()
    storage.attach_file("orig-notes.txt", b"hello", "text/plain")
    db.session.add(FileAttachment(work_item_id=story.id, uploaded_by_id=u("dev.one").id, original_name="notes.txt",
                                  stored_name="orig-notes.txt", mime_type="text/plain", size_bytes=5,
                                  tenant_id=story.tenant_id))
    db.session.commit()
    copy = operations.clone_item(u("dev.one"), story, include_subtasks=True, include_links=True,
                                 include_attachments=True)
    db.session.commit()
    assert copy.title.startswith("CLONE - ") and copy.story_points == 3 and [l.label for l in copy.labels] == ["ui"]
    assert WorkItem.query.filter_by(parent_id=copy.id).count() == 1 and sub.parent_id == story.id
    links = {(row.link_type, row.target_id) for row in WorkItemLink.query.filter_by(source_id=copy.id)}
    assert ("clones", story.id) in links and ("blocks", other.id) in links
    copied = FileAttachment.query.filter_by(work_item_id=copy.id).one()
    assert copied.stored_name != "orig-notes.txt"
    assert storage.read_file(copied.stored_name, copied.stored_name)[0] == b"hello"
    expect_abort(403, operations.clone_item, u("viewer.one"), story)


def test_move_gives_a_new_key_keeps_the_old_one_and_moves_subtasks(pm):
    web, ops = project(), project("OPS")
    component = releases.save_component(u("database.manager"), web, "Frontend")
    db.session.commit()
    story = service.create_item(u("dev.one"), web, "Story", item_type="story", component_ids=[component.id],
                                assignee_ids=[u("dev.two").id])
    service.create_item(u("dev.one"), web, "Sub", item_type="subtask", parent_id=story.id)
    db.session.commit()
    service.remove_member(u("database.manager"), ops, u("dev.two").id)
    db.session.commit()
    operations.move_item(u("dev.one"), story, ops, item_type="bug")
    db.session.commit()
    db.session.expire_all()
    assert story.key == "OPS-1" and story.item_type == "bug" and story.components == []
    assert story.assignees == []  # dev.two cannot work in OPS
    assert WorkItem.query.filter_by(parent_id=story.id).one().key == "OPS-2"
    assert operations.resolve_alias(u("dev.one"), "WEB-1").id == story.id
    assert operations.resolve_alias(u("outsider"), "WEB-1") is None
    assert WorkItemKeyAlias.query.count() == 2
    hidden = project("HID")
    service.remove_member(u("database.manager"), hidden, u("dev.one").id)
    db.session.commit()
    item = service.create_item(u("dev.one"), web, "Stay")
    expect_abort(403, operations.move_item, u("dev.one"), item, hidden)


def test_convert_between_subtask_and_standard_types(pm):
    web = project()
    story = service.create_item(u("dev.one"), web, "Story", item_type="story")
    task = service.create_item(u("dev.one"), web, "Task")
    db.session.commit()
    operations.convert_item(u("dev.one"), task, "subtask", story.id)
    assert task.item_type == "subtask" and task.parent_id == story.id
    expect_abort(409, operations.convert_item, u("dev.one"), story, "subtask", None)  # it has a subtask
    operations.convert_item(u("dev.one"), task, "bug")
    assert task.item_type == "bug" and task.parent_id is None
    expect_abort(400, operations.convert_item, u("dev.one"), task, "bug")  # same type


def test_bulk_change_checks_every_item_and_the_project(pm):
    web, other = project(), project("OTH")
    items = [service.create_item(u("dev.one"), web, f"Item {n}") for n in range(3)]
    foreign = service.create_item(u("dev.one"), other, "Foreign")
    db.session.commit()
    ids = [item.id for item in items]
    assert operations.bulk_change(u("dev.one"), web, ids, "priority", "high") == 3
    assert {item.priority for item in items} == {"high"}
    operations.bulk_change(u("dev.one"), web, ids, "status", status(web, "done").id)
    assert all(item.resolution for item in items)
    expect_abort(400, operations.bulk_change, u("dev.one"), web, ids + [foreign.id], "priority", "low")
    expect_abort(403, operations.bulk_change, u("viewer.one"), web, ids, "priority", "low")
    expect_abort(400, operations.bulk_change, u("dev.one"), web, ids, "explode")
    expect_abort(403, operations.bulk_change, u("dev.two"), web, ids, "delete")  # not reporter or admin
    assert operations.bulk_change(u("database.manager"), web, ids, "delete") == 3


# --- link types and Markdown --------------------------------------------------------------------

def test_link_types_are_per_tenant_and_renames_keep_links(pm):
    web = project()
    a, b = service.create_item(u("dev.one"), web, "A"), service.create_item(u("dev.one"), web, "B")
    custom = catalog.save_link_type(u("admin"), "tests", "tests", "is tested by")
    service.add_link(u("dev.one"), a, "tests", b.key)
    db.session.commit()
    with pm.test_request_context():
        assert [row["relation"] for row in service.links_for(u("dev.one"), b)] == ["is tested by"]
    catalog.save_link_type(u("admin"), "verifies", "verifies", "is verified by", link_type_id=custom.id)
    db.session.commit()
    assert WorkItemLink.query.filter_by(link_type="verifies").count() == 1
    expect_abort(403, catalog.save_link_type, u("dev.one"), "x", "x", "y")
    assert catalog.link_type_named(u("other.admin").tenant_id, "verifies") is None
    expect_abort(400, service.add_link, u("dev.one"), a, "nonexistent", b.key)
    catalog.delete_link_type(u("admin"), custom.id)
    db.session.commit()
    assert WorkItemLink.query.count() == 0


@pytest.mark.parametrize("text", [
    "<script>alert(1)</script>", "[x](javascript:alert(1))", "<img src=x onerror=alert(1)>",
    '[x](https://a.com" onmouseover="alert(1))', "```\n<b>raw</b>\n```", "| a |\n|---|\n| <i>x</i> |",
])
def test_markdown_never_emits_user_html(text):
    html = str(markdown.render(text))
    # Escaped text may still read "onerror=alert"; what matters is that no
    # tag, attribute or javascript: link comes out.
    for unsafe in ("<script", "<img", "<b>", "<i>", 'href="javascript', ' onmouseover="', ' onerror="'):
        assert unsafe not in html, (unsafe, html)


def test_markdown_renders_the_jira_like_subset():
    html = str(markdown.render("# T\n**b** *i* ~~s~~ `c`\n- one\n1. two\n> q\n[l](https://e.com)"))
    for fragment in ("<h3>T</h3>", "<strong>b</strong>", "<em>i</em>", "<del>s</del>", "<code>c</code>",
                     "<ul><li>one</li></ul>", "<ol><li>two</li></ol>", "<blockquote>q</blockquote>",
                     'href="https://e.com"'):
        assert fragment in html


# --- pages and API --------------------------------------------------------------------------------

def _login(client, username, password="Passw0rd!x"):
    client.get("/logout")
    client.post("/login", data={"username": username, "password": password})


def test_pages_and_admin_only_actions(pm, client):
    web = project()
    item = service.create_item(u("dev.one"), web, "Page check", description="See **bold**")
    db.session.commit()
    _login(client, "dev.one")
    for path in (f"/work-items/{item.key}", "/projects/WEB/releases", "/projects/WEB/components", "/your-work",
                 "/your-work?tab=viewed", "/work-items/new", f"/work-items/{item.key}/print"):
        assert client.get(path).status_code in (200, 302), path
    assert "<strong>bold</strong>" in client.get(f"/work-items/{item.key}").get_data(as_text=True)
    assert client.post("/projects/WEB/releases", data={"action": "save", "name": "1.0"}).status_code == 403
    assert client.post("/projects/WEB/components", data={"action": "save", "name": "X"}).status_code == 403
    assert client.get("/projects/admin").status_code == 403
    preview = client.post("/projects/markdown-preview", json={"text": "<b>x</b> **y**"}).get_json()["html"]
    assert "<b>x" not in preview and "<strong>y</strong>" in preview
    _login(client, "outsider")
    assert client.get(f"/work-items/{item.key}/print").status_code == 404
    assert client.post(f"/work-items/{item.key}/vote").status_code == 404
    login(client)
    assert client.get("/projects/admin").status_code == 200


def test_api_phase2_fields_and_endpoints(pm, client):
    web = project()
    component = releases.save_component(u("database.manager"), web, "Frontend")
    version = releases.save_version(u("database.manager"), web, "1.0")
    db.session.commit()
    with pm.app_context():
        token, prefix, token_hash = create_api_token()
        dev = u("dev.one")
        db.session.add(APIClient(name="pm2", token_prefix=prefix, token_hash=token_hash,
                                 scopes_json=json.dumps(["projects:read", "projects:write"]), acting_user_id=dev.id,
                                 created_by_id=dev.id, tenant_id=dev.tenant_id))
        db.session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/api/v1/projects/WEB/work-items", headers={**headers, "Idempotency-Key": "p2-1"},
                          json={"title": "API", "component_ids": [component.id], "fix_version_ids": [version.id],
                                "environment": "Prod", "flagged": True, "estimate_minutes": 120})
    assert created.status_code == 201, created.json
    data = created.json["data"]
    assert data["components"] == ["Frontend"] and data["fix_versions"] == ["1.0"] and data["flagged"] is True
    key = data["key"]
    logged = client.post(f"/api/v1/work-items/{key}/worklogs", headers=headers, json={"time_spent": "1h 30m"})
    assert logged.status_code == 201 and logged.json["data"]["minutes"] == 90
    assert client.get(f"/api/v1/work-items/{key}", headers=headers).json["data"]["remaining_minutes"] == 30
    assert client.post(f"/api/v1/work-items/{key}/worklogs", headers=headers, json={"time_spent": 5}).status_code == 400
    assert client.post(f"/api/v1/work-items/{key}/votes", headers=headers).status_code == 409  # own report
    assert [c["name"] for c in client.get("/api/v1/projects/WEB/components", headers=headers).json["data"]] == ["Frontend"]
    assert [v["name"] for v in client.get("/api/v1/projects/WEB/versions", headers=headers).json["data"]] == ["1.0"]
    assert client.patch(f"/api/v1/work-items/{key}", headers=headers, json={"flagged": "yes"}).status_code == 400
    assert client.patch(f"/api/v1/work-items/{key}", headers=headers, json={"component_ids": []}).json["data"][
        "components"] == []
