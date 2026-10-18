"""Neighboring filter controls retain equal heights in every density."""
import os
from pathlib import Path
import pytest
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import _axe, _sign_in, server, pytestmark  # noqa: F401


@pytest.mark.parametrize('compact,touch', [(False,False),(True,False),(True,True)])
def test_neighbor_controls_match(server,compact,touch):
    from playwright.sync_api import sync_playwright
    _,base=server
    with sync_playwright() as playwright:
        browser=playwright.chromium.launch()
        page=browser.new_page(viewport={'width':390 if touch else 1440,'height':1000},has_touch=touch,is_mobile=touch)
        _sign_in(page,base)
        for route,selector in (('/projects/WEB/board','.project-filters'),('/projects/WEB/backlog','.backlog-controls .planning-toolbar'),('/projects/WEB/timeline','.timeline-filter-toolbar')):
            page.goto(base+route)
            page.wait_for_load_state('networkidle')
            if compact:
                page.evaluate("document.body.classList.add('density-compact')")
            toggle=page.locator('.project-filters-toggle')
            if toggle.count() and toggle.is_visible() and page.locator('.project-filters-wrap').get_attribute('open') is None:
                toggle.click()
            form=page.locator(selector).first
            assert form.is_visible()
            sizes=form.evaluate("""form=>Array.from(form.querySelectorAll('input,select,button,.button')).filter(e=>{const s=getComputedStyle(e);return e.getBoundingClientRect().width && s.opacity!=='0' && s.display!=='none' && e.type!=='hidden'}).map(e=>({tag:e.tagName,height:e.getBoundingClientRect().height,font:getComputedStyle(e).fontSize}))""")
            assert len(sizes)>=2
            heights={round(row['height'],1) for row in sizes}
            assert len(heights)==1, sizes
            assert next(iter(heights))==(44 if touch else 34 if compact else 38)
            assert len({row['font'] for row in sizes})==1,sizes
            if route.endswith('/timeline'):
                action_heights=page.locator('.project-view-heading .actions').evaluate("""row=>Array.from(row.querySelectorAll('button,summary.button')).filter(e=>e.checkVisibility() && !e.hidden).map(e=>e.getBoundingClientRect().height)""")
                assert len(set(action_heights))==1,action_heights
            assert not _axe(page)
            if os.getenv('SERVICEOPS_LAYOUT_SCREEN_DIR'):
                output=Path(os.environ['SERVICEOPS_LAYOUT_SCREEN_DIR'])
                output.mkdir(parents=True,exist_ok=True)
                page.screenshot(path=str(output/f"{route.rsplit('/',1)[-1]}-{'touch' if touch else 'compact' if compact else 'standard'}.png"))
        browser.close()
