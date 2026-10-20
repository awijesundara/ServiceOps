"""Real browser checks for incident handling: the hold reason follows the State field,
similar incidents can become the parent, the counts and family banner show in the
record body, and the pages pass axe at desktop and phone widths."""
import os
import threading

import pytest
from werkzeug.serving import make_server

from app import RecordLink, SupportGroup, Ticket, db
from tests.test_app import app  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv("RUN_INCIDENT_BROWSER") != "1",
                                reason="RUN_INCIDENT_BROWSER=1 enables real local browser checks")

SHOTS = os.getenv("INCIDENT_BROWSER_SHOTS")


def _axe(page):
    axe = os.getenv("AXE_CORE_PATH")
    assert axe and os.path.isfile(axe), "AXE_CORE_PATH required for accessibility acceptance"
    page.evaluate(open(axe, encoding="utf-8").read())
    violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag',"
                               "values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
    assert not violations, [(v["id"], v["help"], [n["target"] for n in v["nodes"]][:3]) for v in violations]
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def _shot(page, name, width):
    if SHOTS:
        page.screenshot(path=os.path.join(SHOTS, f"{name}-{width}.png"), full_page=True)


@pytest.mark.parametrize("width,height", [(1440, 1000), (390, 844)])
def test_incident_handling_in_a_browser(app, width, height):
    from playwright.sync_api import expect, sync_playwright

    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": width, "height": height}, reduced_motion="reduce").new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base + "/login")
            page.locator('input[name="username"]').fill("admin")
            page.locator('input[name="password"]').fill("Admin123!")
            page.locator("button.primary").click()
            page.wait_for_load_state("networkidle")
            with app.app_context():
                core_apps = SupportGroup.query.filter_by(name="CoreApps").one().id

            # Admin: a rule and a template.
            page.goto(base + "/admin/incident-handling")
            _axe(page)
            rules = page.locator("#rules")
            rules.locator("summary", has_text="New rule").click()
            new_rule = rules.locator("details.gov-tab-new form")
            new_rule.get_by_label("Rule name").fill("Software to CoreApps")
            new_rule.locator('select[name="group_id"]').select_option(str(core_apps))
            new_rule.locator('select[name="category"]').select_option("Software / Application")
            new_rule.get_by_role("button", name="Add rule").click()
            page.wait_for_load_state("networkidle")
            expect(page.get_by_role("status").filter(has_text="Assignment rule saved.")).to_be_visible()
            templates = page.locator("#templates")
            templates.locator("summary", has_text="New template").click()
            new_template = templates.locator("details.gov-tab-new form")
            new_template.get_by_label("Template name").fill("Mail outage")
            new_template.locator('input[name="title"]').fill("Outlook cannot reach the mail server")
            new_template.locator('textarea[name="description"]').fill("Users report a disconnected status.")
            new_template.get_by_role("button", name="Add template").click()
            page.wait_for_load_state("networkidle")
            _shot(page, "incident-admin", width)

            # New incident from the template, routed automatically.
            page.goto(base + "/tickets/new/incident")
            page.get_by_role("link", name="Mail outage").click()
            page.wait_for_load_state("networkidle")
            form = page.locator("#incident-create-form")
            expect(form.locator('input[name="title"]')).to_have_value("Outlook cannot reach the mail server")
            form.locator('select[name="category"]').select_option("Software / Application")
            form.locator('select[name="group_id"]').select_option("auto")
            _axe(page)
            page.get_by_role("button", name="Create incident").first.click()
            page.wait_for_load_state("networkidle")
            with app.app_context():
                first = Ticket.query.filter_by(title="Outlook cannot reach the mail server").one()
                first_id, first_number = first.id, first.number

            # A second, similar incident: the suggestion becomes its parent.
            page.goto(base + "/tickets/new/incident")
            form = page.locator("#incident-create-form")
            form.locator('input[name="title"]').fill("Outlook cannot reach mail server again")
            suggestions = page.locator("[data-similar-incidents]")
            expect(suggestions).to_be_visible()
            expect(suggestions).to_contain_text(first_number)
            suggestions.get_by_role("button", name="Use as parent").click()
            expect(form.locator('input[name="parent_incident"]')).to_have_value(first_number)
            _shot(page, "incident-new", width)
            form.locator('textarea[name="description"]').fill("Same symptoms on floor 2.")
            form.locator('select[name="category"]').select_option("Software / Application")
            form.locator('select[name="group_id"]').select_option(str(core_apps))
            page.get_by_role("button", name="Create incident").first.click()
            page.wait_for_load_state("networkidle")
            with app.app_context():
                child = Ticket.query.filter_by(title="Outlook cannot reach mail server again").one()
                child_id = child.id
                assert RecordLink.query.filter_by(source_id=child_id, link_type="parent_incident",
                                                  target_id=first_id).one()

            # The child shows its parent in the body; the hold reason follows the State field.
            page.goto(base + f"/ticket/{child_id}")
            expect(page.locator(".incident-family")).to_contain_text(f"Child of {first_number}")
            hold = page.locator("[data-hold-reason]")
            expect(hold).to_be_hidden()
            record = page.locator("#incident-record-form")
            record.locator('select[name="state"]').select_option("Pending")
            expect(hold).to_be_visible()
            hold.locator("select").select_option("Awaiting vendor")
            page.locator(".record-actions").get_by_role("button", name="Update", exact=True).click()
            page.wait_for_load_state("networkidle")
            with app.app_context():
                assert db.session.get(Ticket, child_id).hold_reason == "Awaiting vendor"
            expect(page.locator("[data-hold-reason]")).to_be_visible()
            _axe(page)
            _shot(page, "incident-child", width)

            # The parent counts its children, CIs, related records and tasks in the tabs.
            page.goto(base + f"/ticket/{first_id}")
            expect(page.locator(".incident-family")).to_contain_text("Parent of 1 incident")
            tabs = page.locator(".record-section-tabs")
            for label in ("Child incidents (1)", "Affected CIs (0)", "Related records (1)", "Incident tasks (0)"):
                expect(tabs).to_contain_text(label)
            page.locator(".record-more-actions summary").click()
            create_link = page.get_by_role("link", name="Change from this incident")
            expect(create_link).to_be_in_viewport()
            box = create_link.bounding_box()
            assert box["x"] >= 0 and box["x"] + box["width"] <= width
            _axe(page)
            _shot(page, "incident-parent", width)
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
