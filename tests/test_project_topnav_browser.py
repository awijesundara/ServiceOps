"""Workspace section highlighting follows real navigation and deep links."""
import pytest
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server, pytestmark  # noqa: F401


@pytest.mark.parametrize('width,dark', [(1440,False),(1440,True),(1000,False),(390,False)])
def test_top_navigation_tracks_section(server,width,dark):
    from playwright.sync_api import sync_playwright
    _,base=server
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1000})
        _sign_in(page,base)
        for route,label in (('/projects/WEB/board','Projects'),('/your-work','Your work'),('/projects/search','Filters'),('/projects/plans','Plans')):
            page.goto(base+route)
            page.wait_for_load_state('networkidle')
            if dark:
                # Resolve once the stylesheet has loaded. wait_for_function would evaluate a string,
                # which the app's script-src 'self' policy (no unsafe-eval) refuses.
                page.evaluate("""() => new Promise((resolve, reject) => {document.documentElement.classList.add('theme-dark');const link=document.createElement('link');link.rel='stylesheet';link.href='/static/dark.css';link.onload=resolve;link.onerror=reject;document.head.append(link)})""")
            nav=page.locator('.project-global-nav')
            assert nav.is_visible()
            assert nav.locator('a').all_text_contents()==['Your work','Projects','Filters','Plans','Create']
            current=nav.locator('a[aria-current]')
            assert current.count()==1
            assert current.inner_text()==label
            assert current.evaluate("e=>getComputedStyle(e,'::after').height")=='3px'
            current.focus()
            assert current.evaluate("e=>getComputedStyle(e).outlineStyle")!='none'
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            assert not _axe(page)
        browser.close()


def test_current_project_tab_is_visible_after_reload_and_resize(server):
    from playwright.sync_api import sync_playwright
    _,base=server
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch()
        page=browser.new_page(viewport={'width':390,'height':1000})
        _sign_in(page,base)
        for width in (390,320,1000):
            page.set_viewport_size({'width':width,'height':1000})
            page.goto(base+'/projects/WEB/content/reports')
            page.wait_for_load_state('networkidle')
            page.reload(wait_until='networkidle')
            assert page.locator('.project-tabs a[aria-current=page]').evaluate("e=>{const r=e.getBoundingClientRect(),n=e.parentElement.getBoundingClientRect();return r.left>=n.left-1 && r.right<=n.right+1}")
            assert page.evaluate('scrollY')==0
        browser.close()
