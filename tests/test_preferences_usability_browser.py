"""Preferences retain readable grouping, keyboard navigation and saved state."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from app import CiClassPermission, ConfigurationItem, User, UserPreference, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server  # noqa: F401

ARTIFACT_ROOT = Path(os.getenv("SERVICEOPS_UI_ARTIFACT_ROOT", tempfile.gettempdir()))

pytestmark = pytest.mark.skipif(os.getenv("RUN_PROJECTS_BROWSER") != "1", reason="Opt-in browser checks")


@pytest.mark.parametrize("width,theme", [(1440, "light"), (390, "light"), (390, "dark"), (768, "midnight")])
def test_preferences_layout_and_workflows(server, width, theme):
    from playwright.sync_api import expect, sync_playwright

    application, base = server
    application.config["CSRF_ENABLED"] = True
    before = os.getenv("PREFERENCES_AUDIT_PHASE") == "before"
    output = ARTIFACT_ROOT / ("serviceops-preferences-" + ("before" if before else "after"))
    output.mkdir(exist_ok=True)
    with application.app_context():
        user = User.query.filter_by(username="admin").one()
        pref = UserPreference.query.filter_by(user_id=user.id).first() or UserPreference(user_id=user.id)
        pref.theme = theme
        db.session.add(pref)
        db.session.commit()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000}, has_touch=width < 1000, reduced_motion="reduce")
        _sign_in(page, base)
        page.goto(base + "/preferences#notifications", wait_until="networkidle")
        page.screenshot(path=str(output / f"notifications-{width}-{theme}.png"), full_page=True)
        geometry = page.locator(".preference-group").evaluate("""group => {
          const box = e => {const r=e.getBoundingClientRect(),s=getComputedStyle(e);return {x:r.x,y:r.y,width:r.width,height:r.height,borders:[s.borderTopWidth,s.borderRightWidth,s.borderBottomWidth,s.borderLeftWidth]}};
          return {outer:box(group),rows:[...group.querySelectorAll('.preference-row')].map(box),fieldset:box(group.querySelector('fieldset')),overflow:document.documentElement.scrollWidth-innerWidth};
        }""")
        (output / f"geometry-{width}-{theme}.json").write_text(json.dumps(geometry, indent=2))
        if before:
            page.locator('[data-pref-tab="forms"]').click()
            page.screenshot(path=str(output / f"forms-{width}-{theme}.png"), full_page=True)
            browser.close()
            return
        assert geometry["overflow"] <= 1
        # Every row owns equal internal gutters; no divider touches the frame.
        for row in geometry["rows"]:
            assert row["x"] > geometry["outer"]["x"] + 8
            assert row["x"] + row["width"] < geometry["outer"]["x"] + geometry["outer"]["width"] - 8
        assert geometry["rows"][-1]["borders"][2] == "0px"
        expect(page.get_by_role("button", name="Save preferences", exact=True)).to_be_hidden()
        assert page.locator('input[name="email_enabled"]').bounding_box()["height"] >= 44
        assert not _axe(page)
        # An incomplete independent chat form cannot block saving email choices.
        page.locator(".personal-channel-add summary").click()
        page.locator('input[name="endpoint"]').fill("unfinished URL")
        first_type = page.locator('#email-event-types input[type="checkbox"]').first
        first_name = first_type.get_attribute("name")
        first_type.uncheck()
        page.get_by_role("button", name="Save notification preferences", exact=True).click()
        page.wait_for_url("**/preferences#notifications")
        expect(page.locator('[data-pref-panel="notifications"]')).to_be_visible()
        expect(page.locator(f'input[name="{first_name}"]')).not_to_be_checked()
        expect(page.locator(".flash").first).to_contain_text("Notification preferences saved.")
        master = page.locator('input[name="email_enabled"]')
        master.uncheck()
        expect(page.locator(f'input[name="{first_name}"]')).to_be_disabled()
        page.get_by_role("button", name="Save notification preferences", exact=True).click()
        page.wait_for_load_state("networkidle")
        master.check()
        expect(page.locator(f'input[name="{first_name}"]')).not_to_be_checked()
        # Tabs expose current state and support orientation-aware keyboard use.
        tab = page.get_by_role("tab", name="Notifications", exact=True)
        tab.focus()
        tab.press("ArrowLeft" if width <= 900 else "ArrowUp")
        expect(page.get_by_role("tab", name="Forms", exact=True)).to_be_focused()
        expect(page.get_by_role("tab", name="Forms", exact=True)).to_have_attribute("aria-selected", "true")
        slider = page.locator('input[name="font_scale"]')
        slider.focus()
        slider.press("End")
        expect(page.locator("#preference-font-scale-value")).to_have_text("140%")
        page.get_by_role("button", name="Save preferences", exact=True).click()
        page.wait_for_url("**/preferences#forms")
        expect(page.locator('[data-pref-panel="forms"]')).to_be_visible()
        expect(slider).to_have_value("140")
        page.screenshot(path=str(output / f"forms-{width}-{theme}.png"), full_page=True)
        page.evaluate("location.hash = 'lists'")
        expect(page.get_by_role("tab", name="Lists", exact=True)).to_have_attribute("aria-selected", "true")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not _axe(page)
        browser.close()


@pytest.mark.parametrize("width", [1440, 390])
def test_notification_channel_forms_are_not_clipped(server, width):
    from playwright.sync_api import sync_playwright

    _, base = server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000}, reduced_motion="reduce")
        _sign_in(page, base)
        page.goto(base + "/admin/integrations?view=add", wait_until="networkidle")
        for name in ("Google Chat", "Telegram bot"):
            # Native details exposes its summary as the disclosure control.
            summary = page.locator(".provider-card > summary").filter(has=page.locator("strong", has_text=name))
            summary.click()
            form = summary.locator("..").locator(".provider-form")
            page.wait_for_timeout(400)
            assert form.evaluate("e => e.scrollHeight <= e.clientHeight + 1"), (name, width, "form content is clipped")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (name, width)
            assert not _axe(page)
            form.locator("button.primary").scroll_into_view_if_needed()
            assert form.locator("button.primary").is_visible()
            output = ARTIFACT_ROOT / "serviceops-preferences-after"
            output.mkdir(exist_ok=True)
            page.screenshot(path=str(output / f"provider-{name.replace(' ', '-')}-{width}.png"), full_page=True)
        browser.close()


@pytest.mark.parametrize("width,theme", [(1440, "light"), (390, "dark")])
def test_permission_columns_and_keyboard_table_scrolling(server, width, theme):
    from playwright.sync_api import expect, sync_playwright

    application, base = server
    with application.app_context():
        user = User.query.filter_by(username="admin").one()
        pref = UserPreference.query.filter_by(user_id=user.id).first() or UserPreference(user_id=user.id)
        pref.theme = theme
        db.session.add_all([pref, ConfigurationItem(name="UI permission test", ci_class="Server", tenant_id=1),
                           CiClassPermission(tenant_id=1, ci_class="Server", role="agent", can_read=True, can_update=False)])
        db.session.commit()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000}, reduced_motion="reduce", has_touch=width < 1000)
        _sign_in(page, base)
        page.goto(base + "/cmdb/permissions", wait_until="networkidle")
        expect(page.get_by_label("Update Server for Agent", exact=True)).not_to_be_checked()
        expect(page.locator(".ci-permissions-table tbody tr").first).to_contain_text("Always allowed")
        columns = page.locator(".ci-permissions-table").evaluate("""table => ({
          head:[...table.tHead.rows[0].cells].reduce((n,c)=>n+c.colSpan,0),
          body:[...table.tBodies[0].rows[0].cells].reduce((n,c)=>n+c.colSpan,0)})""")
        assert columns["head"] == columns["body"] == 10
        if width == 390:
            scroller = page.locator(".task-list-scroll")
            expect(scroller).to_have_attribute("tabindex", "0")
            scroller.focus()
            page.keyboard.press("ArrowRight")
            page.wait_for_timeout(200)
            assert scroller.evaluate("e=>e.scrollLeft") > 0
            assert scroller.evaluate("e=>getComputedStyle(e).outlineStyle") != "none"
        assert not _axe(page)
        output = ARTIFACT_ROOT / "serviceops-preferences-after"
        output.mkdir(exist_ok=True)
        page.screenshot(path=str(output / f"ci-permissions-{width}-{theme}.png"), full_page=True)
        browser.close()
