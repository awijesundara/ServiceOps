"""The email services pages stay usable and accessible."""
from serviceops_models import MailService, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server  # noqa: F401
from tests.test_projects_browser import pytestmark  # noqa: F401

SHOTS = "/private/tmp/claude-501/-Volumes-project/847ade3e-6216-4c88-a0ff-2f5764724e8b/scratchpad"


def test_email_services_pages(server, app):
    from playwright.sync_api import sync_playwright
    _, base = server
    with app.app_context():
        for name, provider, config, flags in (
            ("SendGrid", "sendgrid", {"MAIL_API_KEY": "SG.x", "SMTP_FROM": "desk@example.test"}, {"is_default": True, "last_test_ok": True}),
            ("Corporate relay", "smtp", {"SMTP_HOST": "relay.corp.test", "SMTP_FROM": "desk@example.test"}, {"is_fallback": True}),
        ):
            service = MailService(name=name, provider=provider, **flags)
            service.config = config
            db.session.add(service)
        db.session.commit()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            _sign_in(page, base)
            page.goto(base + "/admin/email")
            page.wait_for_load_state("networkidle")
            assert page.locator(".email-service").count() == 2
            assert page.locator(".email-provider-card").count() == 9
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert not _axe(page)
            page.screenshot(path=f"{SHOTS}/email-services-{width}.png", full_page=True)

            page.goto(base + "/admin/email/new/microsoft365")
            page.wait_for_load_state("networkidle")
            tenant = page.locator('input[name="MS_TENANT_ID"]')
            host = page.locator('input[name="SMTP_HOST"]')
            assert tenant.is_visible() and not host.is_visible()
            page.locator('input[name="method"][value="relay"]').check()
            assert host.is_visible() and not tenant.is_visible()
            assert host.evaluate("e => e.required") and not tenant.evaluate("e => e.required")
            page.locator('input[name="method"][value="graph"]').check()
            assert not _axe(page)
            page.screenshot(path=f"{SHOTS}/email-form-{width}.png", full_page=True)
            page.close()
        browser.close()


def test_email_preferences_grey_out_with_the_master_switch(server):
    from playwright.sync_api import sync_playwright
    _, base = server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 1100})
        _sign_in(page, base)
        page.goto(base + "/preferences#notifications")
        page.locator('[data-pref-tab="notifications"]').click()
        master = page.locator('input[name="email_enabled"]')
        group = page.locator("#email-event-types")
        types = group.locator('input[type="checkbox"]')
        assert master.is_checked() and types.count() > 3
        assert all(types.nth(i).is_checked() for i in range(types.count())), "every email type starts on"
        page.screenshot(path=f"{SHOTS}/prefs-email-on.png", full_page=True)
        master.uncheck(force=True)
        assert group.evaluate("e => e.disabled") and types.first.is_disabled()
        assert "Turn on email notifications to choose." in group.inner_text()
        page.screenshot(path=f"{SHOTS}/prefs-email-off.png", full_page=True)
        master.check(force=True)
        assert not types.first.is_disabled()
        assert not _axe(page)
        browser.close()
