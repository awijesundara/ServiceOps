"""Administration quick find: word matching, ranking, other areas, settings pages and Enter."""
import os
import threading

import pytest
from werkzeug.serving import make_server

from tests.test_app import app, client, login  # noqa: F401

SECTIONS = ("people-access", "service-configuration", "connections-channels", "automation-content",
            "platform-security")


def test_navigation_ranking_and_plurals(client):
    login(client)
    labels = lambda q: [row["label"] for row in client.get("/ui/search/navigation", query_string={"q": q}).get_json()]  # noqa: E731
    assert labels("users")[0] == "Users and access"
    assert "Team managers" in labels("teams")
    assert "Sign-in and directory" in labels("sso")


@pytest.mark.parametrize("section", SECTIONS)
def test_every_admin_area_renders_quick_find(client, section):
    login(client)
    page = client.get(f"/admin/section/{section}").get_data(as_text=True)
    assert "data-admin-quick-find-form" in page and "data-admin-other-card" in page


@pytest.mark.skipif(os.getenv("RUN_ADMIN_QUICK_FIND_BROWSER") != "1", reason="opt-in browser acceptance")
@pytest.mark.parametrize("theme", ["light", "dark"])
def test_admin_quick_find_browser(app, theme):
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
            page = browser.new_page(viewport={"width": 1440, "height": 1000}, color_scheme=theme)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base + "/login")
            page.locator("[name=username]").fill("admin")
            page.locator("[name=password]").fill("Admin123!")
            page.locator("button.primary").click()
            page.wait_for_load_state("networkidle")
            page.goto(base + "/admin/section/people-access")
            box = page.get_by_role("searchbox", name="Find an administration tool")
            visible = lambda: [t.split("\n")[0] for t in page.locator("[data-admin-quick-find-card]:visible").all_inner_texts()]  # noqa: E731

            # A word in every description no longer matches everything: the titled tool comes first.
            box.fill("users")
            first = page.locator("[data-admin-quick-find-card]:visible").evaluate_all(
                "cards => cards.sort((a, b) => (+getComputedStyle(a).order) - (+getComputedStyle(b).order))[0].querySelector('strong').textContent")
            assert first == "Users"
            # Several words in any order, and plurals.
            box.fill("permissions roles")
            assert visible() == ["Roles & permissions"]
            box.fill("teams")
            assert "Team managers & aliases" in visible()
            # Tools in other areas and settings pages are found from here.
            box.fill("service offerings")
            expect(page.locator("[data-admin-other-card]:visible", has_text="Service offerings")).to_be_visible()
            box.fill("ldap")
            expect(page.locator("[data-admin-other-card]:visible", has_text="Sign-in & directory")).to_be_visible()
            # Pages with no administration card come from the settings catalogue.
            box.fill("organization chart")
            expect(page.locator("[data-admin-remote-results] a", has_text="Organization chart")).to_be_visible()
            expect(page.locator("[data-admin-search-all]")).to_contain_text("organization chart")
            # Enter opens the best match.
            box.fill("service offerings")
            page.locator("[data-admin-other-card]:visible").first.wait_for()
            box.press("Enter")
            page.wait_for_url("**/service-operations/settings/service-offerings")
            # No match at all falls back to global search.
            page.goto(base + "/admin/section/people-access")
            box = page.get_by_role("searchbox", name="Find an administration tool")
            box.fill("qwertyzz")
            expect(page.locator("[data-admin-quick-find-empty]")).to_be_visible()
            page.wait_for_timeout(400)
            box.press("Enter")
            page.wait_for_url("**/ui/search?q=qwertyzz")
            assert errors == []
            browser.close()
    finally:
        server.shutdown()
