"""Browser acceptance for cross-project query, saved filters, favourites and export."""
import os
from pathlib import Path

import pytest

from app import User, UserPreference, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _axe, _sign_in  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_PROJECTS_BROWSER')!='1',reason='Requires real Chromium and axe')


@pytest.mark.parametrize('width,theme',[(1440,'light'),(390,'light'),(1440,'dark'),(390,'dark')])
def test_search_save_favourite_export_and_accessibility(server,width,theme):
    from playwright.sync_api import expect, sync_playwright
    application,base=server
    with application.app_context():
        admin=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme=theme; db.session.add(pref); db.session.commit()
    with sync_playwright() as p:
        browser=p.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1000})
        errors=[]; page.on('pageerror',lambda error: errors.append(str(error)))
        _sign_in(page,base)
        page.goto(base+'/projects/search'); page.wait_for_load_state('networkidle')
        page.get_by_label('Query',exact=True).fill('project=WEB AND type=story ORDER BY key DESC')
        page.get_by_role('button',name='Search',exact=True).click()
        page.wait_for_load_state('networkidle')
        expect(page.locator('.project-table tbody tr')).to_have_count(3)
        page.get_by_text('Save this query',exact=True).click()
        page.get_by_label('Filter name',exact=True).fill('Portal backlog')
        page.get_by_role('button',name='Save new filter',exact=True).click()
        page.wait_for_load_state('networkidle')
        expect(page.get_by_text('Filter saved.',exact=True)).to_be_visible()
        expect(page.get_by_text('Portal backlog',exact=True).first).to_be_visible()
        page.get_by_role('button',name='Add favourite',exact=True).click()
        page.wait_for_load_state('networkidle')
        expect(page.get_by_role('button',name='Remove favourite',exact=True)).to_be_visible()
        with page.expect_download() as download:
            page.get_by_role('button',name='Export CSV',exact=True).click()
        assert download.value.suggested_filename=='serviceops-work-items.csv'
        page.get_by_text('Save this query',exact=True).click()
        page.get_by_label('Query to save',exact=True).fill('type=bug')
        page.get_by_role('button',name='Update filter',exact=True).click()
        page.wait_for_load_state('networkidle')
        expect(page.get_by_text('No work items match.',exact=True)).to_be_visible()
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
        page.get_by_label('Query',exact=True).fill('assignee = currentUser() OR type = story')
        page.get_by_role('button',name='Search',exact=True).click()
        page.wait_for_load_state('networkidle')
        assert not _axe(page)
        expect(page.get_by_role('status')).to_contain_text('This query has unsaved changes.')
        capture=os.getenv('SERVICEOPS_SEARCH_SCREENSHOT_DIR')
        if capture:
            Path(capture).mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(Path(capture)/f'search-{width}-{theme}.png'),full_page=True)
        page.get_by_label('Query',exact=True).fill('unknownField = 1')
        page.get_by_role('button',name='Search',exact=True).click()
        page.wait_for_load_state('networkidle')
        expect(page.locator('#query-error')).to_contain_text('Unsupported field')
        assert not _axe(page)
        assert not errors
        browser.close()
