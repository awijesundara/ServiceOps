"""Complete planning journeys and the shared ServiceOps navigation in Chromium."""
import os
from pathlib import Path

import pytest

from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _axe, _sign_in  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_PROJECTS_BROWSER')!='1',reason='Requires Chromium and axe')


@pytest.mark.parametrize('width,theme',[(1440,'light'),(390,'light'),(1440,'dark'),(390,'dark')])
def test_plan_review_calendar_goals_team_and_backlog(server,width,theme):
    from playwright.sync_api import sync_playwright,expect
    from app import db,User,UserPreference
    from serviceops_core.projects import service
    from serviceops_core.projects.models import Project,WorkItem
    application,base=server
    with application.app_context():
        actor=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=actor.id).first() or UserPreference(user_id=actor.id)
        pref.theme=theme;db.session.add(pref)
        row=Project.query.filter_by(key='WEB').one()
        a=WorkItem.query.filter_by(project_id=row.id,number=2).one();b=WorkItem.query.filter_by(project_id=row.id,number=3).one()
        service.add_link(actor,a,'blocks',b.key);db.session.commit()
    screenshots=os.getenv('SERVICEOPS_PLANNING_SCREENSHOT_DIR')
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':width,'height':1000})
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        _sign_in(page,base)
        page.goto(base+'/projects/WEB/timeline',wait_until='networkidle')
        expect(page.locator('[data-plan-row]')).to_have_count(4)
        expect(page.locator('[data-plan-connectors] path[data-edge]')).to_have_count(1)
        page.get_by_role('button',name='Collapse all',exact=True).click()
        expect(page.locator('[data-plan-row]:visible')).to_have_count(1)
        page.get_by_role('button',name='Expand all',exact=True).click()
        expect(page.locator('[data-plan-row]:visible')).to_have_count(4)
        assert page.locator('.timeline-record>a').nth(1).bounding_box()['width']>=150
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        if width==1440:
            colors=page.evaluate("({project:getComputedStyle(document.querySelector('.sidebar')).backgroundImage,text:getComputedStyle(document.querySelector('.sidebar .nav-home')).color})")
            assert 'gradient' in colors['project'] or theme=='dark'
        if screenshots:
            Path(screenshots).mkdir(parents=True,exist_ok=True);page.screenshot(path=str(Path(screenshots)/f'timeline-{width}-{theme}.png'),full_page=True)
        page.get_by_text('Auto-schedule',exact=True).click()
        page.get_by_label('Plan name',exact=True).fill('Portal planning proposal')
        page.get_by_label('Schedule from',exact=True).fill('2026-10-19')
        page.get_by_role('button',name='Preview schedule',exact=True).click();page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading',name='Portal planning proposal')).to_be_visible()
        assert not _axe(page)
        with application.app_context():assert WorkItem.query.filter_by(number=2).one().start_date is None
        page.get_by_role('button',name='Apply selected changes',exact=True).click();page.wait_for_load_state('networkidle')
        expect(page.get_by_text('Selected date changes saved.',exact=True)).to_be_visible()
        with application.app_context():assert WorkItem.query.filter_by(number=2).one().start_date is not None
        page.goto(base+'/projects/WEB/calendar?month=2026-12',wait_until='networkidle')
        expect(page.locator('.calendar-day')).to_have_count(35)
        assert not _axe(page)
        page.goto(base+'/projects/WEB/goals',wait_until='networkidle')
        page.get_by_text('Create goal',exact=True).click()
        page.get_by_label('Goal title',exact=True).fill('Deliver portal accessibility')
        page.get_by_label('Goal description',exact=True).fill('Validate the release evidence.')
        page.get_by_label('Target date',exact=True).fill('2026-12-01')
        page.locator('select[name=item_keys]').select_option(['WEB-2','WEB-3'],force=True)
        page.get_by_role('button',name='Save goal',exact=True).click();page.wait_for_load_state('networkidle')
        expect(page.get_by_role('heading',name='Deliver portal accessibility')).to_be_visible()
        assert not _axe(page)
        page.goto(base+'/projects/WEB/team',wait_until='networkidle');assert not _axe(page)
        page.goto(base+'/projects/WEB/backlog/groups',wait_until='networkidle')
        page.get_by_label('Status for WEB-2',exact=True).select_option(label='In progress')
        page.get_by_label('Points for WEB-2',exact=True).fill('8')
        page.locator('form#group-edit-2').get_by_role('button',name='Save',exact=True).click();page.wait_for_load_state('networkidle')
        assert '/backlog/groups' in page.url
        expect(page.get_by_label('Status for WEB-2',exact=True)).to_have_value('2')
        page.get_by_text('View settings',exact=True).click()
        page.get_by_label('Compact rows',exact=True).check()
        page.get_by_label('Story points',exact=True).uncheck()
        page.get_by_role('button',name='Save view settings',exact=True).click();page.wait_for_load_state('networkidle')
        expect(page.get_by_text('View settings saved.',exact=True)).to_be_visible()
        expect(page.get_by_label('Points for WEB-2',exact=True)).to_have_count(0)
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        if screenshots:page.screenshot(path=str(Path(screenshots)/f'backlog-{width}-{theme}.png'),full_page=True)
        assert not errors
        browser.close()
