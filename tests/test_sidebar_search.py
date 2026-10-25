"""The sidebar box filters the menu, finds pages without a menu link and falls back to global search."""
import os
import threading

import pytest
from werkzeug.serving import make_server

from tests.test_app import app, client, login  # noqa: F401


def test_navigation_search_is_permission_filtered(client):
    login(client)
    labels = [row["label"] for row in client.get("/ui/search/navigation?q=service offerings").get_json()]
    assert "Service offerings" in labels
    # Every word must match, in any order, like record search.
    assert "Service offerings" in [row["label"] for row in client.get("/ui/search/navigation?q=offerings service").get_json()]
    client.post("/logout")
    login(client, "employee", "Employee123!")
    assert client.get("/ui/search/navigation?q=service offerings").get_json() == []
    assert client.get("/ui/search/navigation?q=").get_json() == []


def test_navigation_search_requires_sign_in(client):
    response = client.get("/ui/search/navigation?q=users")
    assert response.status_code in (302, 401)


@pytest.mark.skipif(os.getenv("RUN_SIDEBAR_SEARCH_BROWSER") != "1", reason="opt-in browser acceptance")
@pytest.mark.parametrize("width,theme", [(1440, "light"), (1440, "dark")])
def test_sidebar_search_browser(app, width, theme):
    from playwright.sync_api import expect, sync_playwright
    from app import User, UserPreference, db
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        preference = UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        preference.theme = theme
        db.session.add(preference)
        db.session.commit()
    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": width, "height": 1000}, color_scheme=theme)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base + "/login")
            page.locator("[name=username]").fill("admin")
            page.locator("[name=password]").fill("Admin123!")
            page.locator("button.primary").click()
            page.wait_for_load_state("networkidle")
            box = page.get_by_role("searchbox", name="Find a menu item or search ServiceOps")

            # A page with no sidebar link is still found, and Enter opens the single match.
            box.fill("service offerings")
            results = page.locator("[data-nav-search-pages] a")
            expect(results.filter(has_text="Service offerings")).to_be_visible()
            expect(page.locator("[data-nav-filter-empty]")).to_be_hidden()
            box.press("Enter")
            page.wait_for_url("**/service-operations/settings/service-offerings")

            # Sidebar links still filter in place.
            box = page.get_by_role("searchbox", name="Find a menu item or search ServiceOps")
            box.fill("incidents")
            expect(page.locator("[data-application-nav] .nav-group-items a:visible", has_text="Incidents")).to_be_visible()

            # Anything else goes to the full global search.
            box.fill("printer jam")
            all_link = page.locator("[data-nav-search-all]")
            expect(all_link).to_contain_text("printer jam")
            box.press("Enter")
            page.wait_for_url("**/ui/search?q=printer+jam")
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
