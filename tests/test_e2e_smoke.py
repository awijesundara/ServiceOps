"""Real-browser smoke test against a running ServiceOps instance.

This is the first *persisted* browser-automation coverage this repo has
ever had (see BACKLOG item #15 / B-297): every prior live-UI check in this
project's history was an ephemeral Playwright install inside a throwaway
verification context, never a tracked dependency or a test file that lives
in the repo -- so there was zero standing regression coverage for anything
a unit test can't see (JS errors, real rendering, real navigation).

Deliberately NOT part of the normal `pytest` run (Dockerfile.test does not
install `requirements-e2e.txt`, and this file is skipped unless
E2E_BASE_URL is set) -- it needs a real running instance and a real
browser binary, neither of which belong in the unit-test/CI gate. To run
it against a live stack:

    pip install -r requirements-e2e.txt
    playwright install chromium
    E2E_BASE_URL=http://localhost E2E_ADMIN_PASSWORD=<bootstrap admin password> \
        pytest tests/test_e2e_smoke.py -v

This is a first standing thread for item #15, not full closure of it --
load, failover, accessibility, LDAP, Keycloak, SMTP, Teams, and Kubernetes
evidence all still need real staging infrastructure this repo's own test
suite cannot provide.
"""
import os

import pytest

BASE_URL = os.environ.get("E2E_BASE_URL", "").rstrip("/")
ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "")

pytestmark = pytest.mark.skipif(
    not BASE_URL, reason="set E2E_BASE_URL to run real-browser smoke tests against a live instance"
)


@pytest.fixture(scope="module")
def browser():
    playwright_module = pytest.importorskip("playwright.sync_api")
    with playwright_module.sync_playwright() as p:
        browser = p.chromium.launch()
        yield browser
        browser.close()


def test_login_dashboard_and_cmdb_navigation_have_no_console_errors(browser):
    assert ADMIN_PASSWORD, "set E2E_ADMIN_PASSWORD to the live instance's bootstrap admin password"
    console_errors = []
    page = browser.new_page()
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

    page.goto(f"{BASE_URL}/login")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', ADMIN_PASSWORD)
    page.click("button.primary")
    page.wait_for_load_state("networkidle")
    assert "/login" not in page.url, "login did not redirect away from the login page"

    page.goto(f"{BASE_URL}/cmdb")
    page.wait_for_load_state("networkidle")
    assert page.url.endswith("/cmdb")

    page.close()
    assert console_errors == [], f"browser console errors during smoke test: {console_errors}"
