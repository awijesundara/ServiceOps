"""Blocking browser, responsive-layout, and accessibility journeys.

The suite runs against a disposable Compose project in CI. Locally:

    playwright install chromium
    E2E_BASE_URL=http://localhost E2E_ADMIN_PASSWORD=... \
      pytest tests/test_e2e_smoke.py -v

Set ``AXE_CORE_PATH`` to an installed ``axe.min.js`` to run WCAG scanning.
CI always sets it; local runs fail rather than silently skipping accessibility.
"""

import os
from pathlib import Path

import pytest


BASE_URL = os.environ.get("E2E_BASE_URL", "").rstrip("/")
ADMIN_PASSWORD = os.environ.get("E2E_ADMIN_PASSWORD", "")
AXE_CORE_PATH = os.environ.get("AXE_CORE_PATH", "")
ARTIFACT_DIR = Path(os.environ.get("E2E_ARTIFACT_DIR", "test-results/browser"))

pytestmark = pytest.mark.skipif(
    not BASE_URL, reason="set E2E_BASE_URL to run browser tests against a disposable instance"
)


@pytest.fixture(scope="session")
def browser():
    playwright_module = pytest.importorskip("playwright.sync_api")
    with playwright_module.sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture(scope="session")
def authenticated_storage(browser):
    """Authenticate once; individual viewport contexts reuse the session.

    Logging in separately for every route eventually exercises the production
    login rate limiter instead of the pages under test, especially after the
    wide-screen viewport expanded this matrix.
    """
    assert ADMIN_PASSWORD, "E2E_ADMIN_PASSWORD is required"
    context = browser.new_context()
    page = context.new_page()
    page.goto(f"{BASE_URL}/login", wait_until="networkidle")
    page.fill('input[name="username"]', "admin")
    page.fill('input[name="password"]', ADMIN_PASSWORD)
    page.click("button.primary")
    page.wait_for_load_state("networkidle")
    assert "/login" not in page.url, "bootstrap administrator login failed"
    storage = context.storage_state()
    context.close()
    return storage


@pytest.fixture(params=[
    pytest.param({"name": "wide-desktop", "width": 2560, "height": 1440}, id="wide-desktop"),
    pytest.param({"name": "desktop", "width": 1440, "height": 1000}, id="desktop"),
    pytest.param({"name": "mobile", "width": 390, "height": 844}, id="mobile"),
])
def authenticated_page(browser, authenticated_storage, request):
    assert AXE_CORE_PATH and Path(AXE_CORE_PATH).is_file(), "AXE_CORE_PATH must point to axe.min.js"
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    viewport = request.param
    # axe-core is injected by the test runner rather than served by the app.
    # Bypass CSP only in this disposable browser context; the live response
    # header remains strict and application scripts are still checked for
    # console errors under that policy.
    context = browser.new_context(
        viewport={"width": viewport["width"], "height": viewport["height"]},
        bypass_csp=True,
        storage_state=authenticated_storage,
    )
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    page = context.new_page()
    console_errors = []
    page.on("console", lambda message: console_errors.append(message.text) if message.type == "error" else None)
    setup_failed = False
    try:
        yield page, viewport["name"], console_errors
    except Exception:
        setup_failed = True
        raise
    finally:
        call_report = getattr(request.node, "rep_call", None)
        failed = setup_failed or bool(call_report and call_report.failed)
        safe_name = request.node.name.replace("/", "-")
        if failed:
            page.screenshot(path=ARTIFACT_DIR / f"{safe_name}.png", full_page=True)
            context.tracing.stop(path=ARTIFACT_DIR / f"{safe_name}.zip")
        else:
            context.tracing.stop()
        context.close()


CORE_WORKFLOWS = (
    ("dashboard", "/"),
    ("administration", "/admin"),
    ("user-profile", "/profile"),
    ("login-sessions", "/profile/sessions"),
    ("team-management", "/service-operations/settings/team-managers"),
    ("directory-sync", "/service-operations/settings/ldap-sync"),
    ("cmdb", "/cmdb"),
    ("cmdb-import", "/cmdb/import"),
    ("client-management", "/client-management"),
)


@pytest.mark.parametrize("journey,path", CORE_WORKFLOWS, ids=[item[0] for item in CORE_WORKFLOWS])
def test_critical_journey_is_responsive_error_free_and_accessible(authenticated_page, journey, path):
    page, viewport_name, console_errors = authenticated_page
    response = page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
    assert response and response.ok, f"{journey} returned HTTP {response.status if response else 'no response'}"
    assert page.locator("main").is_visible(), f"{journey} has no visible main region at {viewport_name} width"
    if viewport_name == "wide-desktop":
        main_box = page.locator("main").bounding_box()
        assert main_box and main_box["x"] + main_box["width"] >= 2559, (
            f"{journey} leaves unused horizontal space at 2560px: {main_box}"
        )
    if journey == "cmdb-import":
        if not page.locator(".netbox-mapping-details").evaluate("element => element.open"):
            page.locator(".netbox-mapping-details summary").click()
        page.screenshot(path=ARTIFACT_DIR / f"cmdb-import-{viewport_name}.png", full_page=True)

    page.add_script_tag(path=AXE_CORE_PATH)
    axe_result = page.evaluate("""async () => await axe.run(document, {
        runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']},
        resultTypes: ['violations']
    })""")
    blocking = [
        violation for violation in axe_result["violations"]
        if violation.get("impact") in {"critical", "serious"}
    ]
    assert not blocking, (
        f"{journey} has blocking accessibility violations at {viewport_name}: "
        + "; ".join(f"{item['id']} ({len(item['nodes'])} nodes)" for item in blocking)
    )
    assert console_errors == [], f"{journey} console errors at {viewport_name}: {console_errors}"
