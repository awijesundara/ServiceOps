"""Shared controls and active navigation remain usable across themes and sizes."""
import pytest

from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server  # noqa: F401
from tests.test_projects_browser import pytestmark  # noqa: F401


@pytest.mark.parametrize("dark,width", [(False, 1440), (True, 1440), (False, 390)])
def test_shared_controls_and_current_project_tab(server, dark, width):
    from playwright.sync_api import sync_playwright
    _, base = server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 1000})
        _sign_in(page, base)
        for route in ("/projects/WEB/board", "/projects/WEB/backlog"):
            page.goto(base + route)
            page.wait_for_load_state("networkidle")
            if dark:
                page.evaluate("document.documentElement.classList.add('theme-dark')")
                # Resolve on load: a string wait_for_function needs unsafe-eval, which the CSP refuses.
                page.evaluate("""() => new Promise((resolve, reject) => {const link = document.createElement('link');
                  link.rel='stylesheet';link.href='/static/dark.css';link.onload=resolve;link.onerror=reject;document.head.append(link)})""")
            current = page.locator('.project-tabs a[aria-current="page"]')
            assert current.count() == 1
            indicator = current.evaluate("e => {const s=getComputedStyle(e,'::after');return {height:s.height,background:s.backgroundColor}}")
            assert indicator["height"] == "3px"
            assert indicator["background"] != "rgba(0, 0, 0, 0)"
            current.focus()
            assert current.evaluate("e=>getComputedStyle(e).outlineStyle") != "none"
            assert not _axe(page)
        page.goto(base + "/tickets/new/incident")
        page.wait_for_load_state("networkidle")
        field = page.locator('input[name="title"]')
        assert field.count() == 1
        assert field.evaluate("e=>getComputedStyle(e).borderRadius") == "6px"
        assert field.bounding_box()["height"] >= 38
        field.focus()
        assert field.evaluate("e=>getComputedStyle(e).outlineStyle") != "none"
        assert not _axe(page)
        page.goto(base + "/preferences")
        page.wait_for_load_state("networkidle")
        switch = page.locator('input[name="reduced_motion"]')
        switch.check(force=True)
        assert switch.is_checked()
        radio = page.locator('input[name="theme"][value="navy"]')
        radio.locator('..').click()
        assert radio.is_checked()
        assert not _axe(page)
        browser.close()
