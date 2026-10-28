"""The email delivery settings page stays usable and accessible."""
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server  # noqa: F401
from tests.test_projects_browser import pytestmark  # noqa: F401


def test_email_delivery_settings_page(server):
    from playwright.sync_api import sync_playwright
    _, base = server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        for width in (1440, 390):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            _sign_in(page, base)
            page.goto(base + "/admin/settings/email_delivery")
            page.wait_for_load_state("networkidle")
            assert page.locator('select[name="MAIL_TRANSPORT"] option').count() == 8
            assert page.locator('textarea[name="SMTP_CA_CERT"]').count() == 1
            assert page.locator('textarea[name="MS_CLIENT_CERTIFICATE"]').count() == 1
            assert page.locator("#email-test button").is_visible()
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert not _axe(page)
            page.screenshot(path=f"/private/tmp/claude-501/-Volumes-project/847ade3e-6216-4c88-a0ff-2f5764724e8b/scratchpad/email-settings-{width}.png", full_page=True)
            page.close()
        browser.close()
