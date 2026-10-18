"""Populated project, plan, structure, program and automation UI acceptance."""
import os
from pathlib import Path

import pytest
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server,_sign_in,_axe  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_PROJECTS_BROWSER')!='1',reason='Requires Chromium and axe')


@pytest.mark.parametrize('width,theme',[(1440,'light'),(390,'light'),(1440,'dark'),(390,'dark')])
def test_premium_workspaces_with_actual_interactions(server,width,theme):
    from playwright.sync_api import sync_playwright,expect
    from app import db,User,UserPreference
    from serviceops_core.projects import advanced_plans as plans,service,automation
    from serviceops_core.projects.models import WorkItem,ProjectAutomationRun
    application,base=server
    with application.app_context():
        actor=User.query.filter_by(username='admin').one();project=service.project_or_404(actor,'WEB')
        pref=UserPreference.query.filter_by(user_id=actor.id).first() or UserPreference(user_id=actor.id);pref.theme=theme;db.session.add(pref)
        for item in WorkItem.query.filter_by(project_id=project.id).filter(WorkItem.item_type!='epic'):
            service.update_item(actor,item,dict(estimate_minutes=480,start_date='2026-10-19',due_date='2026-10-23'))
        plan=plans.create(actor,dict(name='Cloud delivery plan',projects=['WEB'],settings=dict(start='2026-10-19')))
        _,payload=plans.get(actor,plan.id);team=plans.save_team(actor,plan,payload,dict(name='Platform team',capacity=16,unit='hours',members=[actor.id]))
        a=WorkItem.query.filter_by(number=2).one();b=WorkItem.query.filter_by(number=3).one()
        plans.allocate(actor,plan,payload,a.id,team.id,0);plans.allocate(actor,plan,payload,b.id,team.id,1)
        root=WorkItem.query.filter_by(number=1).one();plans.save_node(actor,plan,payload,dict(name='Cloud portfolio',kind='Portfolio',item_keys=[root.key]))
        plans.scenario(actor,plan,'Initial scenario')
        rule=automation.save(actor,dict(name='Complete descendants',enabled=True,projects=['WEB'],config=dict(trigger='transitioned',conditions=[dict(field='item_type',operator='eq',value='epic')],branch='descendants',branch_conditions=[dict(field='category',operator='ne',value='done')],actions=[dict(type='transition',copy_trigger=True)])))
        db.session.commit();plan_id=plan.id;team_id=team.id;rule_id=rule.id
    screenshots=os.getenv('SERVICEOPS_PREMIUM_SCREENSHOT_DIR')
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':width,'height':1000});errors=[]
        page.on('pageerror',lambda error:errors.append(str(error)));_sign_in(page,base)
        routes=[('summary','/projects/WEB/overview'),('timeline','/projects/WEB/timeline?anchor=2026-10-19&zoom=weeks'),('structure',f'/projects/plans/{plan_id}/structure'),('program',f'/projects/plans/{plan_id}/program'),('teams',f'/projects/plans/{plan_id}/teams'),('plan-timeline',f'/projects/plans/{plan_id}/timeline'),('automation',f'/projects/automation/{rule_id}')]
        for name,path in routes:
            response=page.goto(base+path,wait_until='networkidle');assert response.status==200,(name,response.status)
            assert not _axe(page),(name,width,theme)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),name
            if screenshots:
                Path(screenshots).mkdir(parents=True,exist_ok=True);page.screenshot(path=str(Path(screenshots)/f'{name}-{width}-{theme}.png'),full_page=True)
        page.locator('[data-rule-steps]').get_by_role('button').nth(1).click()
        expect(page.get_by_role('heading',name='Issue fields condition',exact=True)).to_be_visible()
        assert page.locator('[data-rule-detail]').get_by_label('Value',exact=True).count()==1,(page.locator('[data-rule-detail]').inner_html(),page.locator('[data-rule-feedback]').text_content())
        page.locator('[data-rule-detail]').get_by_label('Value',exact=True).select_option('epic')
        page.get_by_role('button',name='Save automation rule',exact=True).click();page.wait_for_load_state('networkidle')
        expect(page.get_by_text('Automation rule saved.',exact=True)).to_be_visible()
        page.goto(base+f'/projects/plans/{plan_id}/structure',wait_until='networkidle')
        page.get_by_role('button',name='Collapse all',exact=True).click()
        assert page.locator('[data-structure-node]:visible').count()<5
        page.get_by_role('button',name='Expand all',exact=True).click()
        expect(page.locator('[data-structure-node]:visible')).to_have_count(5)
        page.goto(base+f'/projects/plans/{plan_id}/program',wait_until='networkidle')
        if width==1440:
            card=page.locator('[data-program-card="2"]');cell=page.locator(f'[data-team="{team_id}"][data-iteration="2"]')
            card.drag_to(cell);page.wait_for_load_state('networkidle')
            expect(page.locator(f'[data-team="{team_id}"][data-iteration="2"] [data-program-card="2"]')).to_have_count(1)
        else:
            card=page.locator('[data-program-card="2"]');card.get_by_text('Schedule',exact=True).click()
            card.get_by_label('Iteration',exact=True).select_option('2');card.get_by_role('button',name='Save allocation',exact=True).click();page.wait_for_load_state('networkidle')
        page.goto(base+'/work-items/WEB-1',wait_until='networkidle')
        with page.expect_response(lambda response:response.request.method=='POST' and '/work-items/WEB-1/' in response.url) as saved:
            page.locator('select[name=status_id]').select_option(label='Done')
        assert saved.value.status in (200,302)
        with application.app_context():
            assert WorkItem.query.filter_by(number=2).one().status.category=='done'
            assert ProjectAutomationRun.query.filter_by(rule_id=rule_id).one().outcome=='success'
        assert not errors
        browser.close()


def test_timeline_drag_review_and_intake_journey(server):
    from playwright.sync_api import sync_playwright,expect
    from app import db,User
    from serviceops_core.projects import service
    from serviceops_core.projects.models import WorkItem
    application,base=server
    with application.app_context():
        actor=User.query.filter_by(username='admin').one();item=WorkItem.query.filter_by(number=2).one()
        service.update_item(actor,item,dict(start_date='2026-10-19',due_date='2026-10-23'));db.session.commit();identifier=item.id
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':1600,'height':1000});_sign_in(page,base)
        page.goto(base+'/projects/WEB/timeline?anchor=2026-10-19&zoom=weeks',wait_until='networkidle')
        bar=page.locator(f'[data-plan-bar="{identifier}"]');bar.scroll_into_view_if_needed();rect=bar.bounding_box()
        page.mouse.move(rect['x']+rect['width']/2,rect['y']+12);page.mouse.down();page.mouse.move(rect['x']+rect['width']/2+55,rect['y']+12,steps=10);page.mouse.up()
        expect(page.locator('[data-plan-review]')).to_be_visible()
        with application.app_context():assert db.session.get(WorkItem,identifier).start_date.isoformat()=='2026-10-19'
        page.locator('[data-plan-review]').click();page.wait_for_url('**/planning/drafts/*')
        page.get_by_role('button',name='Apply selected changes',exact=True).click();page.wait_for_load_state('networkidle')
        with application.app_context():assert db.session.get(WorkItem,identifier).start_date.isoformat()!='2026-10-19'
        page.goto(base+'/projects/WEB/content/forms',wait_until='networkidle');page.get_by_text('Create form',exact=True).click()
        editor=page.locator('[data-intake-editor]');editor.get_by_label('Name',exact=True).fill('Platform intake');editor.get_by_role('button',name='Add field',exact=True).click()
        editor.get_by_label('Label',exact=True).fill('Business reason');editor.get_by_label('Required',exact=True).check()
        editor.get_by_role('button',name='Save form',exact=True).click();page.wait_for_load_state('networkidle')
        page.get_by_role('link',name='Open form',exact=True).click();page.wait_for_load_state('networkidle');page.get_by_label('Summary',exact=True).fill('New hosting platform');page.get_by_label('Business reason').fill('Capacity expansion')
        page.screenshot(path='/private/tmp/serviceops-premium-20261018/intake-diagnostic.png',full_page=True)
        violations=_axe(page)
        assert not violations,(violations,page.locator('.project-tabs a').first.evaluate('(e)=>({color:getComputedStyle(e).color,background:getComputedStyle(e.parentElement).backgroundColor,body:getComputedStyle(document.body).backgroundColor,html:document.documentElement.className})'))
        page.get_by_role('button',name='Create work item',exact=True).click();page.wait_for_load_state('networkidle');page.locator('summary').filter(has_text='Submitted form').click();expect(page.get_by_text('Capacity expansion',exact=True)).to_be_visible()
        for view in ('pages','reports','shortcuts'):
            page.goto(base+'/projects/WEB/content/'+view,wait_until='networkidle');assert not _axe(page),view
        browser.close()


@pytest.mark.parametrize('width',[390,1440])
def test_premium_administration_accessibility(server,width):
    from playwright.sync_api import sync_playwright
    from datetime import timedelta
    from app import db,User,now
    from serviceops_core.projects.models import ProjectSandbox
    application,base=server
    with application.app_context():
        actor=User.query.filter_by(username='admin').one();application.config['PREMIUM_SANDBOX_ENABLED']=True
        db.session.add(ProjectSandbox(tenant_id=actor.tenant_id,owner_id=actor.id,name='Synthetic acceptance',slot=1,state='ready',expires_at=now()+timedelta(hours=1)));db.session.commit()
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':width,'height':1000});_sign_in(page,base)
        for section in ('release-tracks','sandboxes','insights','ip-allowlist'):
            response=page.goto(base+'/admin/premium/'+section,wait_until='networkidle');assert response.status==200
            assert not _axe(page),(section,width)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),(section,width)
        browser.close()
