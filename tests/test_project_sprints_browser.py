"""Sprint planning lifecycle, ranking and accessible charts in Chromium."""
import os
from pathlib import Path

import pytest

from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401
from serviceops_core.projects.models import ProjectSprint

pytestmark=pytest.mark.skipif(os.getenv('RUN_PROJECTS_BROWSER')!='1',reason='Requires Chromium and axe')


@pytest.mark.parametrize('width,theme',[(1440,'light'),(390,'light'),(1440,'dark'),(390,'dark')])
def test_sprint_create_assign_rank_start_report_complete(server,width,theme):
    from playwright.sync_api import sync_playwright, expect
    from app import User,UserPreference,db
    application,base=server
    with application.app_context():
        admin=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme=theme; db.session.add(pref); db.session.commit()
    with sync_playwright() as p:
        browser=p.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1000})
        errors=[]; page.on('pageerror',lambda error:errors.append(str(error)))
        _sign_in(page,base)
        page.goto(base+'/projects/WEB/backlog'); page.wait_for_load_state('networkidle')
        page.get_by_text('Create sprint',exact=True).first.click()
        form=page.locator('form[action$="/sprints/save"]')
        form.get_by_label('Sprint name',exact=True).fill('Portal delivery')
        form.get_by_label('Sprint goal',exact=True).fill('Deliver sign-in improvements')
        form.get_by_label('Start (UTC)',exact=True).fill('2026-10-17T08:00')
        form.get_by_label('End (UTC)',exact=True).fill('2026-10-31T08:00')
        form.get_by_role('button',name='Create sprint',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.get_by_text('Sprint saved.',exact=True)).to_be_visible()
        with application.app_context(): sprint_id=ProjectSprint.query.filter_by(name='Portal delivery').one().id
        page.get_by_label('Planning view',exact=True).select_option('')
        page.get_by_role('button',name='Open view',exact=True).click(); page.wait_for_load_state('networkidle')
        page.get_by_label('Select WEB-2',exact=True).check(); page.get_by_label('Select WEB-3',exact=True).check()
        page.get_by_label('Move selected work to',exact=True).select_option(str(sprint_id))
        page.get_by_role('button',name='Move selected',exact=True).click(); page.wait_for_load_state('networkidle')
        assert 'sprint=' not in page.url
        page.get_by_label('Planning view',exact=True).select_option(str(sprint_id))
        page.get_by_role('button',name='Open view',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.locator('[data-backlog-row]')).to_have_count(2)
        page.get_by_role('button',name='Move WEB-3 up',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.locator('[data-backlog-row]').first).to_have_attribute('data-backlog-row','WEB-3')
        if width==1440:
            page.locator('[data-backlog-handle="WEB-2"]').drag_to(page.locator('[data-backlog-handle="WEB-3"]'))
            page.wait_for_load_state('networkidle')
            expect(page.locator('[data-backlog-row]').first).to_have_attribute('data-backlog-row','WEB-2')
        page.get_by_role('button',name='Start sprint',exact=True).click(); page.wait_for_load_state('networkidle')
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        capture=os.getenv('SERVICEOPS_SPRINT_SCREENSHOT_DIR')
        if capture:
            Path(capture).mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(Path(capture)/f'backlog-{width}-{theme}.png'),full_page=True)
        page.get_by_role('link',name='Sprint report and charts',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading',name='Burndown',exact=True)).to_be_visible()
        assert page.locator('#sprint-unit').evaluate('(element) => getComputedStyle(element).backgroundRepeat')=='no-repeat'
        expect(page.get_by_role('heading',name='Burnup',exact=True)).to_be_visible()
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        capture=os.getenv('SERVICEOPS_SPRINT_SCREENSHOT_DIR')
        if capture:
            Path(capture).mkdir(parents=True,exist_ok=True)
            page.screenshot(path=str(Path(capture)/f'sprints-{width}-{theme}.png'),full_page=True)
        page.get_by_role('link',name='Open sprint',exact=True).click(); page.wait_for_load_state('networkidle')
        page.get_by_role('button',name='Complete sprint',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading',name='Velocity · last 10 completed sprints',exact=True)).to_be_visible()
        assert not _axe(page)
        page.get_by_role('link',name='Browse all sprints and history',exact=True).click(); page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading',name='All sprints',exact=True)).to_be_visible()
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
        assert not errors
        browser.close()
