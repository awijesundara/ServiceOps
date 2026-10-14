"""Project management rules (B-443): access, numbering, validation, history,
notifications, links and queries. Negative authorization and tenant
isolation cases are part of each area."""
import pytest
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from app import (Notification, PlatformSetting, Tenant, Ticket, User, create_ticket_with_unique_number, db)
from serviceops_core.projects import service
from serviceops_core.projects.models import Project, ProjectMember, WorkItem, WorkItemHistory
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
    """Projects enabled, plus developers, an outsider and a user of another tenant."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        other = Tenant(slug="pm-other", name="Other organisation")
        db.session.add(other)
        db.session.flush()
        for name in ("dev.one", "dev.two", "outsider"):
            _user(name)
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


def make_project(key="WEB", visibility="private", members=(("dev.one", "member"),)):
    project = service.create_project(u("database.manager"), key, f"{key} project", visibility=visibility)
    for username, role in members:
        service.set_member(u("database.manager"), project, u(username).id, role)
    db.session.commit()
    return project


def test_projects_are_off_until_enabled_and_creators_follow_the_setting(app):
    with app.app_context():
        assert not service.can_create_projects(User.query.filter_by(username="admin").one())
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        db.session.commit()
        assert service.can_create_projects(u("database.manager"))
        assert not service.can_create_projects(u("employee"))
        db.session.merge(PlatformSetting(key="PROJECTS_CREATORS", value="everyone", tenant_id=admin.tenant_id))
        db.session.commit()
        assert service.can_create_projects(u("employee"))


def test_create_project_validates_the_key_and_sets_up_statuses_and_admins(pm):
    project = make_project()
    assert [s.name for s in project.statuses] == ["To do", "In progress", "In review", "Done"]
    assert {m.user.username: m.role for m in project.members} == {"database.manager": "admin", "dev.one": "member"}
    expect_abort(409, service.create_project, u("database.manager"), "web", "Duplicate")
    for bad in ("1AB", "A", "TOOLONGKEY1", "A-B"):
        expect_abort(400, service.create_project, u("database.manager"), bad, "Bad key")
    expect_abort(403, service.create_project, u("employee"), "EMP", "Requesters cannot create")
    assert service.suggest_key("Customer Portal Redesign") == "CPR"


def test_visibility_private_open_tenant_admin_and_other_tenant(pm):
    private, open_project = make_project("PRIV"), make_project("OPEN", visibility="open")
    assert service.project_role(u("dev.one"), private) == "member"
    assert service.project_role(u("outsider"), private) is None
    assert service.project_role(u("outsider"), open_project) == "reader"
    assert service.project_role(u("admin"), private) == "admin"  # tenant administrator
    assert service.project_role(u("other.admin"), open_project) is None  # other tenant
    expect_abort(404, service.project_or_404, u("outsider"), "PRIV")
    expect_abort(404, service.project_or_404, u("other.admin"), "OPEN")
    keys = {p.key for p in service.visible_projects(u("outsider"))}
    assert keys == {"OPEN"}
    assert {p.key for p in service.visible_projects(u("other.admin"))} == set()


def test_items_are_numbered_per_project_and_notify_assignees(pm):
    project = make_project(members=(("dev.one", "member"), ("dev.two", "member")))
    first = service.create_item(u("dev.one"), project, "Build login page", assignee_ids=[u("dev.two").id])
    second = service.create_item(u("dev.one"), project, "Write tests")
    db.session.commit()
    assert (first.key, second.key) == ("WEB-1", "WEB-2")
    assert first.status.name == "To do" and first.reporter.username == "dev.one"
    note = Notification.query.filter_by(user_id=u("dev.two").id, target_type="work_item").one()
    assert "WEB-1" in note.title
    assert service.is_watching(first, u("dev.one")) and service.is_watching(first, u("dev.two"))
    # Only members who can edit may be assigned; an outsider cannot.
    expect_abort(400, service.create_item, u("dev.one"), project, "x", assignee_ids=[u("outsider").id])
    expect_abort(400, service.create_item, u("dev.one"), project, "")


def test_roles_limit_editing_and_commenting(pm):
    project = make_project(visibility="open", members=(("dev.one", "member"), ("dev.two", "viewer")))
    item = service.create_item(u("dev.one"), project, "Task")
    db.session.commit()
    expect_abort(403, service.update_item, u("dev.two"), item, {"title": "Viewer edit"})
    service.add_comment(u("dev.two"), item, "Viewers may comment")
    expect_abort(403, service.add_comment, u("outsider"), item, "Readers may not")
    expect_abort(403, service.update_item, u("outsider"), item, {"title": "Reader edit"})
    expect_abort(403, service.create_item, u("outsider"), project, "Reader create")
    service.set_archived(u("database.manager"), project, True)
    expect_abort(403, service.update_item, u("dev.one"), item, {"title": "Archived"})


def test_updates_record_history_resolve_and_notify_watchers(pm):
    project = make_project(members=(("dev.one", "member"), ("dev.two", "member")))
    item = service.create_item(u("dev.one"), project, "Fix bug", item_type="bug")
    service.set_watching(u("dev.two"), item, True)
    db.session.commit()
    done = next(s for s in project.statuses if s.category == "done")
    service.update_item(u("dev.one"), item, {"status_id": done.id, "priority": "high", "title": "Fix the bug",
                                             "labels": "frontend urgent", "due_date": "2026-11-01"})
    db.session.commit()
    fields = {h.field for h in WorkItemHistory.query.filter_by(work_item_id=item.id)}
    assert {"status", "priority", "title", "labels", "due_date"} <= fields
    assert item.resolved_at is not None and [l.label for l in item.labels] == ["frontend", "urgent"]
    moved = Notification.query.filter(Notification.user_id == u("dev.two").id,
                                      Notification.title.like("% moved to %")).one()
    assert "Done" in moved.title
    assert Notification.query.filter(Notification.user_id == u("dev.one").id,
                                     Notification.title.like("% moved to %")).count() == 0
    todo = next(s for s in project.statuses if s.category == "todo")
    service.update_item(u("dev.one"), item, {"status_id": todo.id})
    assert item.resolved_at is None
    expect_abort(400, service.update_item, u("dev.one"), item, {"due_date": "not a date"})
    expect_abort(400, service.update_item, u("dev.one"), item, {"start_date": "2026-12-01", "due_date": "2026-11-01"})
    expect_abort(400, service.update_item, u("dev.one"), item, {"story_points": "-3"})


def test_hierarchy_rules(pm):
    project = make_project()
    epic = service.create_item(u("dev.one"), project, "Epic", item_type="epic")
    story = service.create_item(u("dev.one"), project, "Story", item_type="story", parent_id=epic.id)
    sub = service.create_item(u("dev.one"), project, "Sub", item_type="subtask", parent_id=story.id)
    db.session.commit()
    assert sub.parent.id == story.id and story.parent.id == epic.id
    expect_abort(400, service.create_item, u("dev.one"), project, "Orphan", item_type="subtask")
    expect_abort(400, service.create_item, u("dev.one"), project, "Story under story", item_type="story",
                 parent_id=story.id)
    expect_abort(400, service.create_item, u("dev.one"), project, "Sub under epic", item_type="subtask",
                 parent_id=epic.id)
    expect_abort(400, service.create_item, u("dev.one"), project, "Epic child", item_type="epic", parent_id=epic.id)
    other = make_project("OTH")
    elsewhere = service.create_item(u("database.manager"), other, "Epic elsewhere", item_type="epic")
    expect_abort(400, service.create_item, u("dev.one"), project, "Cross project", item_type="story",
                 parent_id=elsewhere.id)
    expect_abort(409, service.update_item, u("dev.one"), story, {"item_type": "subtask", "parent_id": story.id})


def test_board_moves_order_items_between_neighbours(pm):
    project = make_project()
    a, b, c = (service.create_item(u("dev.one"), project, name) for name in "ABC")
    db.session.commit()
    service.move_item(u("dev.one"), c, before_id=a.id, after_id=b.id)
    in_progress = next(s for s in project.statuses if s.name == "In progress")
    service.move_item(u("dev.one"), a, status_id=in_progress.id)
    db.session.commit()
    todo = service.item_query(project, {"status": str(service.default_status(project).id)})
    assert [i.title for i in service.sorted_query(todo, "rank")] == ["C", "B"]
    assert a.status_id == in_progress.id


def test_mentions_notify_only_people_who_can_see_the_project(pm):
    project = make_project(members=(("dev.one", "member"), ("dev.two", "member")))
    item = service.create_item(u("dev.one"), project, "Discuss")
    db.session.commit()
    service.add_comment(u("dev.one"), item, "@dev.two and @outsider please look")
    db.session.commit()
    assert Notification.query.filter(Notification.user_id == u("dev.two").id,
                                     Notification.title.like("%mentioned you%")).count() == 1
    assert Notification.query.filter_by(user_id=u("outsider").id).count() == 0


def test_links_to_items_and_itsm_records_respect_visibility(pm):
    project, hidden = make_project(), make_project("HID", members=())
    item = service.create_item(u("dev.one"), project, "Implement change")
    other = service.create_item(u("dev.one"), project, "Prerequisite")
    secret = service.create_item(u("database.manager"), hidden, "Hidden")
    change = create_ticket_with_unique_number("change", title="Upgrade", description="x", priority="P3",
                                              requester_id=u("dev.one").id)
    db.session.commit()
    service.add_link(u("dev.one"), other, "blocks", item.key)
    service.add_link(u("dev.one"), item, "relates", change.number)
    db.session.commit()
    with pm.test_request_context():  # ITSM links resolve to page URLs
        rows = service.links_for(u("dev.one"), item)
    assert {r["relation"] for r in rows} == {"is blocked by", "relates to"}
    assert {r["label"] for r in rows} == {other.key, change.number}
    expect_abort(400, service.add_link, u("dev.one"), item, "relates", secret.key)  # cannot see HID
    expect_abort(409, service.add_link, u("dev.one"), other, "blocks", item.key)
    expect_abort(400, service.add_link, u("dev.one"), item, "relates", item.key)
    assert [i.key for i in service.items_linked_to_record(u("dev.one"), "ticket", change.id)] == [item.key]
    assert service.items_linked_to_record(u("outsider"), "ticket", change.id) == []


def test_only_reporter_or_project_admin_deletes(pm):
    project = make_project(members=(("dev.one", "member"), ("dev.two", "member")))
    item = service.create_item(u("dev.one"), project, "Mine")
    db.session.commit()
    expect_abort(403, service.delete_item, u("dev.two"), item)
    service.delete_item(u("dev.one"), item)
    db.session.commit()
    assert WorkItem.query.count() == 0


def test_queries_and_search_respect_visibility(pm):
    project, hidden = make_project(), make_project("HID", members=())
    bug = service.create_item(u("dev.one"), project, "Login button broken", item_type="bug", priority="high",
                              assignee_ids=[u("dev.one").id], labels="frontend")
    service.create_item(u("dev.one"), project, "Docs page", item_type="task")
    service.create_item(u("database.manager"), hidden, "Login secret plan")
    db.session.commit()
    assert [i.key for i in service.item_query(project, {"type": "bug"})] == [bug.key]
    assert [i.key for i in service.item_query(project, {"assignee": "me"}, u("dev.one"))] == [bug.key]
    assert [i.key for i in service.item_query(project, {"label": "FRONTEND"})] == [bug.key]
    assert [i.key for i in service.item_query(project, {"q": "WEB-1"})] == [bug.key]
    assert service.item_query(project, {"assignee": "none"}).count() == 1
    assert [i.key for i in service.search(u("dev.one"), "login")] == [bug.key]
    assert service.search(u("outsider"), "login") == []
    assert {i.key for i in service.search(u("admin"), "login")} == {bug.key, "HID-1"}  # tenant admin
    assert service.search(u("dev.one"), "HID-1") == []
    assert [i.key for i in service.my_open_items(u("dev.one"))] == [bug.key]


def test_member_management_keeps_an_administrator(pm):
    project = make_project()
    manager = u("database.manager")
    expect_abort(409, service.remove_member, manager, project, manager.id)
    expect_abort(403, service.set_member, u("dev.one"), project, u("dev.two").id, "member")
    expect_abort(400, service.set_member, manager, project, u("other.admin").id, "member")  # other tenant
    service.remove_member(manager, project, u("dev.one").id)
    db.session.commit()
    assert ProjectMember.query.filter_by(project_id=project.id).count() == 1
    assert Project.query.count() == 1
