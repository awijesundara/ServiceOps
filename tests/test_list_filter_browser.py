"""Dashboard drill-down keeps applied filters without opening their editor."""
import os
import threading

import pytest

from tests.test_app import app  # noqa: F401
from tests.test_dashboards import _seed_tickets

pytestmark = pytest.mark.skipif(os.getenv("RUN_LIST_FILTER_BROWSER") != "1",
                                reason="Set RUN_LIST_FILTER_BROWSER=1 for browser checks")


@pytest.fixture()
def server(app):
    from werkzeug.serving import make_server
    from app import SupportGroup
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name="Database").one().id
    _seed_tickets(app, group_id)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}"
    finally:
        srv.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize("width", [1440, 390])
def test_dashboard_filtered_list_editor_opens_only_on_request(server, width):
    from playwright.sync_api import expect, sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(server + "/login")
        page.fill('input[name="username"]', "admin")
        page.fill('input[name="password"]', "Admin123!")
        page.click("button.primary")
        page.goto(server + "/dashboards")
        page.locator('.dash-tiles a', has_text="Priority 1 and 2").click()
        page.wait_for_url("**/tickets/all?*")
        editor = page.locator(".list-filter-builder")
        toggle = page.locator(".list-filter-toggle")
        expect(editor).to_be_hidden()
        expect(toggle).to_have_attribute("aria-expanded", "false")
        expect(page.locator(".list-breadcrumb")).to_contain_text("Priority 1 or 2")
        expect(page.locator(".task-list tbody")).to_contain_text("Seed 1")
        expect(page.locator(".task-list tbody")).not_to_contain_text("Seed 2")
        toggle.click()
        expect(editor).to_be_visible()
        expect(toggle).to_have_attribute("aria-expanded", "true")
        expect(editor.locator(".filter-row")).to_have_count(3)
        page.keyboard.press("Escape")
        expect(editor).to_be_hidden()
        expect(toggle).to_be_focused()
        toggle.click()
        page.locator(".list-filter-add").click()
        expect(editor.locator(".filter-row")).to_have_count(4)
        editor.locator(".filter-row-remove").last.click()
        editor.get_by_role("button", name="Run", exact=True).click()
        page.wait_for_load_state("networkidle")
        expect(editor).to_be_hidden()
        expect(page.locator(".task-list tbody")).to_contain_text("Seed 1")
        toggle.click()
        page.get_by_role("banner").click(position={"x": 100, "y": 20})
        expect(editor).to_be_hidden()
        expect(toggle).to_have_attribute("aria-expanded", "false")
        toggle.click()
        editor.get_by_role("button", name="Clear filter", exact=True).click()
        page.wait_for_load_state("networkidle")
        expect(editor).to_be_hidden()
        expect(page.locator(".task-list tbody")).to_contain_text("Seed 2")
        assert not errors
        browser.close()
