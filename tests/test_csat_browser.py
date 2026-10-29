"""The satisfaction rating on a resolved record is one compact, accessible row."""
from app import Ticket, User, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server  # noqa: F401
from tests.test_projects_browser import pytestmark  # noqa: F401

SHOTS = "/private/tmp/claude-501/-Volumes-project/847ade3e-6216-4c88-a0ff-2f5764724e8b/scratchpad"


def test_rating_bar_layout(server, app):
    from playwright.sync_api import sync_playwright
    _, base = server
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(number="CHG0009911", kind="change", title="New change", description="test", category="Software",
                        priority="P3", impact="Medium", urgency="Medium", requester_id=admin_id, state="Resolved",
                        tenant_id=1)
        db.session.add(ticket)
        db.session.commit()
        ticket_id = ticket.id
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width, dark in ((1440, False), (1440, True), (390, False)):
            page = browser.new_page(viewport={"width": width, "height": 900})
            _sign_in(page, base)
            page.goto(f"{base}/ticket/{ticket_id}")
            page.wait_for_load_state("networkidle")
            if dark:
                page.evaluate("document.documentElement.classList.add('theme-dark')")
                page.evaluate("""() => new Promise((resolve, reject) => {const link = document.createElement('link');
                  link.rel='stylesheet';link.href='/static/dark.css';link.onload=resolve;link.onerror=reject;document.head.append(link)})""")
            options = page.locator(".csat-option")
            assert options.count() == 5
            tops = {round(options.nth(i).bounding_box()["y"]) for i in range(5)}
            assert len(tops) == 1, "all five choices sit on one row"
            options.nth(3).click()
            assert page.locator('input[name="rating"][value="4"]').is_checked()
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert not _axe(page)
            page.locator(".csat").screenshot(path=f"{SHOTS}/csat-{width}-{'dark' if dark else 'light'}.png")
            page.close()
        browser.close()


def test_change_review_prompt_is_first_and_accessible(server, app):
    from playwright.sync_api import sync_playwright
    from app import ApprovalChain
    _, base = server
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        ticket = Ticket(number="CHG0009912", kind="change", title="New change", description="test", category="Software",
                        priority="P3", impact="Medium", urgency="Medium", requester_id=admin_id, state="Resolved",
                        tenant_id=1)
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ApprovalChain(name="CAB", target_type="ticket", target_id=ticket.id, state="Approved", tenant_id=1))
        db.session.commit()
        ticket_id = ticket.id
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            _sign_in(page, base)
            page.goto(f"{base}/ticket/{ticket_id}")
            page.wait_for_load_state("networkidle")
            prompt = page.locator("#change-review")
            assert prompt.is_visible()
            assert not _axe(page)
            page.screenshot(path=f"{SHOTS}/change-review-{width}.png")
            page.close()
        browser.close()
