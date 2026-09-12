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
    ("all-workspaces", "/modules"),
    ("service-catalog", "/catalog"),
    ("serviceops-mobile", "/mobile-app"),
    ("administration", "/admin"),
    ("administration-connections", "/admin/section/connections-channels"),
    ("administration-platform", "/admin/section/platform-security"),
    ("settings-security", "/admin/settings/security"),
    ("settings-notifications", "/admin/integrations"),
    ("personal-notifications", "/preferences#notifications"),
    ("user-profile", "/profile"),
    ("login-sessions", "/profile/sessions"),
    ("team-management", "/service-operations/settings/team-managers"),
    ("directory-sync", "/service-operations/settings/ldap-sync"),
    ("audit-evidence", "/admin/audit"),
    ("cmdb", "/cmdb"),
    ("cmdb-import", "/cmdb/import"),
    ("client-management", "/client-management"),
)

CARD_LAYOUT_PAGES = (
    ("all-workspaces", "/modules", ".module-card"),
    ("service-catalog", "/catalog", ".catalog-item"),
    ("serviceops-mobile", "/mobile-app", ".mobile-card"),
)

# Every page carrying a .task-list-scroll wide table, for the dedicated
# laptop-width (1024-1440px) no-horizontal-scroll check below. audit-evidence
# is deliberately excluded (see the comment in the test that checks it at
# 1440px) since every one of its columns carries distinct forensic detail
# that column-hiding would remove rather than just declutter.
WIDE_TABLE_PAGES = (
    ("tickets-incident", "/tickets/incident"),
    ("tickets-change", "/tickets/change"),
    ("requests", "/requests"),
    ("assets", "/assets"),
    ("known-errors", "/known-errors"),
    ("improvements", "/improvements"),
    ("cmdb", "/cmdb"),
    ("system-health", "/admin/system-health"),
    ("system-health-logs", "/admin/system-health/logs"),
    ("module-records-problem", "/module/problem"),
)


@pytest.fixture(params=[
    pytest.param({"name": "laptop-narrow", "width": 1024, "height": 768}, id="laptop-narrow"),
    pytest.param({"name": "laptop-wide", "width": 1440, "height": 900}, id="laptop-wide"),
])
def laptop_width_page(browser, authenticated_storage, request):
    viewport = request.param
    context = browser.new_context(
        viewport={"width": viewport["width"], "height": viewport["height"]},
        storage_state=authenticated_storage,
    )
    page = context.new_page()
    try:
        yield page, viewport["name"]
    finally:
        context.close()


@pytest.mark.parametrize("journey,path", WIDE_TABLE_PAGES, ids=[item[0] for item in WIDE_TABLE_PAGES])
def test_wide_table_fits_without_horizontal_scroll_at_laptop_widths(laptop_width_page, journey, path):
    page, viewport_name = laptop_width_page
    response = page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
    assert response and response.ok, f"{journey} returned HTTP {response.status if response else 'no response'}"
    overflow = page.evaluate(
        """() => Array.from(document.querySelectorAll('.task-list-scroll'))
            .filter(el => el.scrollWidth > el.clientWidth + 1)
            .map(el => ({scrollWidth: el.scrollWidth, clientWidth: el.clientWidth}))"""
    )
    assert not overflow, f"{journey} has a horizontally-scrolling .task-list at {viewport_name}: {overflow}"


@pytest.mark.parametrize("journey,path,selector", CARD_LAYOUT_PAGES, ids=[item[0] for item in CARD_LAYOUT_PAGES])
def test_card_rows_are_content_driven_equal_height_and_aligned(authenticated_page, journey, path, selector):
    page, viewport_name, _ = authenticated_page
    response = page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
    assert response and response.ok
    cards = page.locator(selector)
    assert cards.count() > 0
    measurements = cards.evaluate_all(
        """cards => cards.map(card => {
            const box = card.getBoundingClientRect();
            const footer = card.querySelector('.card-footer');
            return {
                top: Math.round(box.top),
                height: Math.round(box.height),
                width: Math.round(box.width),
                footerBottom: footer ? Math.round(footer.getBoundingClientRect().bottom) : null
            };
        })"""
    )
    assert all(item["width"] > 0 and item["height"] > 0 for item in measurements)
    if viewport_name != "mobile":
        rows = {}
        for item in measurements:
            rows.setdefault(item["top"], []).append(item)
        for row in rows.values():
            assert max(item["height"] for item in row) - min(item["height"] for item in row) <= 1
            footers = [item for item in row if item["footerBottom"] is not None]
            if len(footers) > 1:
                assert max(item["footerBottom"] for item in footers) - min(item["footerBottom"] for item in footers) <= 1


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
    if journey in {"user-profile", "directory-sync", "audit-evidence", "administration", "administration-connections", "administration-platform", "settings-security", "settings-notifications", "personal-notifications"}:
        page.screenshot(path=ARTIFACT_DIR / f"{journey}-{viewport_name}.png", full_page=True)

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
    # Wide ticket/task tables (.task-list) were redesigned to fit laptop
    # widths (1024-1440px) via progressive column-hiding instead of relying
    # on the horizontal scroll-shadow; at this fixture's 1440px "desktop"
    # width every such table should now fit with no overflow. The audit
    # trail is a deliberate, documented exception (every column carries
    # distinct forensic detail) and keeps the scroll-shadow treatment.
    if viewport_name == "desktop" and journey != "audit-evidence":
        overflow = page.evaluate(
            """() => Array.from(document.querySelectorAll('.task-list-scroll'))
                .filter(el => el.scrollWidth > el.clientWidth + 1)
                .map(el => ({scrollWidth: el.scrollWidth, clientWidth: el.clientWidth}))"""
        )
        assert not overflow, f"{journey} still has a horizontally-scrolling .task-list at 1440px: {overflow}"
