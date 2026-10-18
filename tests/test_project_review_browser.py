"""Regression coverage for board flags, query guidance and narrow sprint actions."""
import os
from pathlib import Path

import pytest

from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _axe, _sign_in  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("RUN_PROJECTS_BROWSER") != "1", reason="Requires Chromium and axe")


@pytest.mark.parametrize("width,theme", [(1440, "light"), (320, "light"), (1440, "dark"), (390, "dark")])
def test_board_flag_search_help_and_sprint_actions(server, width, theme):
    from playwright.sync_api import expect, sync_playwright
    from app import User, UserPreference, db, now
    from datetime import timedelta
    from serviceops_core.projects import service, sprints
    from serviceops_core.projects.models import Project, WorkItem

    application, base = server
    with application.app_context():
        actor = User.query.filter_by(username="admin").one()
        pref = UserPreference.query.filter_by(user_id=actor.id).first() or UserPreference(user_id=actor.id)
        pref.theme = theme
        db.session.add(pref)
        project = Project.query.filter_by(key="WEB").one()
        item = WorkItem.query.filter_by(project_id=project.id, number=2).one()
        service.update_item(actor, item, {"flagged": True})
        sprint = sprints.save(actor, project, {
            "name": "Customer portal delivery and accessibility review",
            "goal": "Exercise action links in a narrow layout.",
            "start_at": now().isoformat(), "end_at": (now() + timedelta(days=14)).isoformat(),
        })
        sprints.assign(actor, project, item.key, sprint.id)
        sprints.start(actor, project, sprint.id)
        sprint_id = sprint.id
        db.session.commit()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        _sign_in(page, base)
        page.goto(base + "/projects/WEB/board", wait_until="networkidle")
        context_nav = page.get_by_role("group", name="Current project navigation", exact=True)
        expect(context_nav.get_by_role("link", name="Board", exact=True)).to_have_attribute("aria-current", "page")
        expect(context_nav.get_by_role("link", name="Backlog", exact=True)).to_have_attribute("href", "/projects/WEB/backlog")
        expect(page.locator(".project-view-heading h2")).to_have_text("Board")
        heading_box = page.locator(".project-head h1").bounding_box()
        assert heading_box and heading_box["y"] >= 60, "Project heading must clear the fixed top bar"
        card = page.locator('[data-item-key="WEB-2"]')
        expect(card.locator(".wi-card-flag")).to_be_visible()
        expect(card.locator(".wi-card-flag")).to_contain_text("Flagged")
        expect(page.locator('[data-item-key="WEB-3"] .wi-card-flag')).to_have_count(0)
        assert not _axe(page)
        capture = os.getenv("SERVICEOPS_REVIEW_SCREENSHOT_DIR")
        if capture:
            Path(capture).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(capture) / f"flags-{width}-{theme}.png"), full_page=True)

        page.goto(base + f"/projects/WEB/backlog?sprint={sprint_id}", wait_until="networkidle")
        expect(page.locator('.sprint-navigation [aria-current="page"]')).to_contain_text("Customer portal delivery")
        actions = page.locator(".sprint-view-actions .button")
        expect(actions).to_have_count(2)
        boxes = [actions.nth(index).bounding_box() for index in range(2)]
        first, second = boxes
        assert first and second
        assert (first["x"] + first["width"] <= second["x"] or
                first["y"] + first["height"] <= second["y"])
        assert all(box["x"] >= 0 and box["x"] + box["width"] <= width for box in boxes)
        if width < 600:
            assert second["y"] >= first["y"] + first["height"]
        assert not _axe(page)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        if capture:
            page.screenshot(path=str(Path(capture) / f"sprint-actions-{width}-{theme}.png"), full_page=True)
        page.get_by_role("link", name="Sprint report and charts", exact=True).click()
        expect(page.get_by_role("heading", name="Burndown", exact=True)).to_be_visible()
        page.goto(base + f"/projects/WEB/backlog?sprint={sprint_id}", wait_until="networkidle")
        page.get_by_role("link", name="Open sprint board", exact=True).click()
        expect(page.locator('[data-item-key="WEB-2"]')).to_have_count(1)
        expect(page.locator('[data-item-key="WEB-3"]')).to_have_count(0)

        page.goto(base + "/projects/search", wait_until="networkidle")
        page.get_by_text("Supported query fields and examples", exact=True).click()
        expect(page.get_by_text("Use openSprints()", exact=False)).to_be_visible()
        expect(page.get_by_text("History, sprint, custom-field and plugin queries are not supported", exact=False)).to_have_count(0)
        page.get_by_label("Query", exact=True).fill("project = WEB AND sprint IN openSprints()")
        page.get_by_role("button", name="Search", exact=True).click()
        page.wait_for_load_state("networkidle")
        expect(page.locator(".project-table tbody tr")).to_have_count(1)
        expect(page.locator(".project-table tbody")).to_contain_text("WEB-2")
        assert not _axe(page)
        assert not errors
        browser.close()
