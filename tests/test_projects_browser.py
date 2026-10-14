"""Project management in a real browser (B-443): drag a card to another
column and within a column, pick assignees, change status inline on the
list, quick-add from the board, and check every project page with axe
(WCAG 2.1 AA) at desktop and phone width, light and dark.

Run with RUN_PROJECTS_BROWSER=1 and AXE_CORE_PATH set."""
import os
import threading

import pytest
from werkzeug.security import generate_password_hash

from app import PlatformSetting, User, UserPreference, db
from serviceops_core.projects import service
from serviceops_core.projects.models import WorkItem
from tests.test_app import app  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("RUN_PROJECTS_BROWSER") != "1",
                                reason="Set RUN_PROJECTS_BROWSER=1 to run the project browser checks")


@pytest.fixture()
def server(app):
    from werkzeug.serving import make_server
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.merge(PlatformSetting(key="PROJECTS_ENABLED", value="true", tenant_id=admin.tenant_id))
        people = []
        for name in ("Aiko Tanaka", "Ben Carter"):
            user = User(username=name.split()[0].lower(), name=name, email=f"{name.split()[0].lower()}@test.invalid",
                        role="agent", password_hash=generate_password_hash("Passw0rd!x"))
            db.session.add(user)
            people.append(user)
        db.session.commit()
        project = service.create_project(admin, "WEB", "Customer Portal", visibility="open")
        for user in people:
            service.set_member(admin, project, user.id, "member")
        epic = service.create_item(admin, project, "Sign-in", item_type="epic")
        for title in ("Alpha", "Bravo", "Charlie"):
            service.create_item(admin, project, title, item_type="story", parent_id=epic.id,
                                assignee_ids=[people[0].id], labels="ui", story_points=3, due_date="2026-12-01")
        service.add_comment(people[0], WorkItem.query.filter_by(number=2).one(), "Looks good @ben")
        db.session.commit()
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield app, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _axe(page):
    path = os.getenv("AXE_CORE_PATH")
    assert path and os.path.isfile(path), "AXE_CORE_PATH required for accessibility acceptance"
    page.evaluate(open(path, encoding="utf-8").read())  # a script tag would be blocked by the CSP
    result = page.evaluate("async () => await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']}})")
    return [(v["id"], [n["target"] for n in v["nodes"]][:3]) for v in result["violations"]]


def _sign_in(page, base):
    page.goto(base + "/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', "Admin123!")
    page.click("button.primary")
    page.wait_for_load_state("networkidle")


def test_board_drag_people_picker_inline_status_and_quick_add(server):
    from playwright.sync_api import expect, sync_playwright
    app, base = server
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        _sign_in(page, base)
        page.goto(base + "/projects/WEB/board")
        columns = page.locator(".project-column-body")
        todo, doing = columns.nth(0), columns.nth(1)
        expect(todo.locator(".wi-card")).to_have_count(3)
        todo.locator('.wi-card[data-item-key="WEB-2"]').drag_to(doing.locator(".project-cards"))
        expect(doing.locator(".wi-card")).to_have_count(1)
        expect(page.locator(".toast")).to_contain_text("WEB-2")
        heads = page.locator(".project-board-heads .project-column-count")
        expect(heads.nth(0)).to_have_text("2")
        expect(heads.nth(1)).to_have_text("1")
        # Reorder within To do: Charlie above Bravo.
        todo.locator('.wi-card[data-item-key="WEB-4"]').drag_to(todo.locator('.wi-card[data-item-key="WEB-3"]'),
                                                                 target_position={"x": 20, "y": 4})
        page.wait_for_timeout(500)
        page.reload()
        expect(page.locator(".project-column-body").nth(1).locator(".wi-card")).to_have_count(1)
        assert page.locator(".project-column-body").nth(0).locator(".wi-card").first.get_attribute(
            "data-item-key") == "WEB-4"

        # Quick add from the board lands in that column.
        page.fill("#quick-" + page.locator(".project-quick-add input[name=status_id]").nth(1).get_attribute("value"),
                  "Quick from board")
        page.locator(".project-quick-add").nth(1).locator("input[name=title]").press("Enter")
        page.wait_for_load_state("networkidle")
        expect(page.locator(".project-column-body").nth(1)).to_contain_text("Quick from board")

        # People picker on the work item page.
        page.goto(base + "/work-items/WEB-3")
        search = page.locator(".people-search")
        search.click()
        search.fill("ben")
        search.press("Enter")
        expect(page.locator(".people-chip")).to_have_count(2)
        page.get_by_role("button", name="Save details").click()
        page.wait_for_load_state("networkidle")
        expect(page.locator(".people-chip")).to_contain_text(["Aiko Tanaka", "Ben Carter"])

        # Inline status on the list.
        page.goto(base + "/projects/WEB/list")
        page.locator('select.wi-inline-status[data-item-key="WEB-3"]').select_option(label="Done")
        expect(page.locator(".toast")).to_contain_text("WEB-3")
        assert not errors, errors
        browser.close()
    with app.app_context():
        item = WorkItem.query.filter_by(number=3).one()
        assert item.status.name == "Done" and {u.username for u in item.assignees} == {"aiko", "ben"}


@pytest.mark.parametrize("width,theme", [(1440, "light"), (390, "light"), (1440, "dark")])
def test_project_pages_have_no_accessibility_violations(server, width, theme):
    from playwright.sync_api import sync_playwright
    app, base = server
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        pref = UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme = theme
        db.session.add(pref)
        db.session.commit()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 900})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        _sign_in(page, base)
        for path in ("/projects", "/projects/new", "/projects/WEB/overview", "/projects/WEB/board", "/projects/WEB/board?swimlane=epic",
                     "/projects/WEB/list?group=status", "/work-items/WEB-2", "/work-items/WEB-1",
                     "/projects/WEB/items/new", "/projects/WEB/settings", "/my/work-items"):
            page.goto(base + path)
            page.wait_for_load_state("networkidle")
            assert _axe(page) == [], (path, width, theme)
            overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            assert overflow <= 1, (path, width, "page scrolls sideways")
        assert not errors, errors
        browser.close()
