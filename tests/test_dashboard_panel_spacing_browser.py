"""Populated dashboard sections share vertical and horizontal spacing."""
import os
from datetime import timedelta
from pathlib import Path
import pytest
from app import SLADefinition, TaskSLA, Ticket, User, UserPreference, db, now
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv('RUN_INTERFACE_SYSTEM_BROWSER') != '1', reason='opt-in dashboard browser check')


@pytest.mark.parametrize('width,dark,compact,touch', [(1440,False,False,False),(1280,True,True,False),(390,False,False,True),(768,True,False,True)])
def test_populated_dashboard_spacing(server,width,dark,compact,touch):
    from playwright.sync_api import sync_playwright
    app,base=server
    with app.app_context():
        admin=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme='dark' if dark else 'light';pref.density='compact' if compact else 'comfortable';db.session.add(pref)
        definition=SLADefinition(name='Dashboard spacing sample',target_type='ticket',duration_minutes=60,tenant_id=1)
        db.session.add(definition);db.session.flush()
        for i,breached in enumerate((True,False)):
            ticket=Ticket(number=f'INC99009{i}',kind='incident',title='Sample incident',description='Synthetic dashboard spacing check',state='New',priority='P3',category='Software',requester_id=admin.id,assignee_id=admin.id,tenant_id=1)
            db.session.add(ticket);db.session.flush()
            db.session.add(TaskSLA(definition_id=definition.id,target_type='ticket',target_id=ticket.id,breached=breached,breach_at=now()+timedelta(hours=-1 if breached else 1)))
        db.session.commit()
    with sync_playwright() as p:
        browser=p.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1100},has_touch=touch,is_mobile=touch)
        _sign_in(page,base)
        for variant in ('both','risk-only','breached-only','none'):
            page.goto(base+'/',wait_until='networkidle')
            assert page.get_by_role('heading',name='Assigned to me',exact=True).count()==1
            assert page.locator('.dashboard-columns>.panel').count()==(2 if variant=='both' else 0 if variant=='none' else 1)
            if variant=='both':
                assert page.get_by_role('heading',name='SLA breached',exact=False).count()==1
                assert page.get_by_role('heading',name='SLA at risk',exact=False).count()==1
            metrics=page.locator('.dashboard-sections').evaluate('''e=>{
              const rect=n=>n.getBoundingClientRect(), children=[...e.children].filter(n=>n.checkVisibility());
              const row=e.querySelector('.dashboard-columns'), cards=row?[...row.children]:[];
              const tips=[...e.querySelectorAll('.panel-head h2>.info-tip')].map(n=>{
                const r=document.createRange();r.selectNodeContents(n.parentElement.firstChild);
                return rect(n).left-r.getBoundingClientRect().right;
              });
              return {gaps:children.slice(1).map((n,i)=>rect(n).top-rect(children[i]).bottom),
                cardGap:cards.length===2?(Math.abs(rect(cards[0]).top-rect(cards[1]).top)<1?rect(cards[1]).left-rect(cards[0]).right:rect(cards[1]).top-rect(cards[0]).bottom):null,
                statsGap:rect(e).top-rect(document.querySelector('main>.stats')).bottom,singleWidth:cards.length===1?Math.abs(rect(cards[0]).width-rect(row).width):0,tips,outside:[...document.querySelectorAll('main *')].filter(n=>n.checkVisibility()&&n.getBoundingClientRect().right>innerWidth+1).map(n=>({tag:n.tagName,cls:n.className,right:n.getBoundingClientRect().right})).slice(0,12),overflow:document.documentElement.scrollWidth>innerWidth+1};
            }''')
            assert abs(metrics['statsGap']-20)<1,metrics
            assert metrics['singleWidth']<1,metrics
            assert metrics['gaps'] and all(abs(gap-20)<1 for gap in metrics['gaps']),metrics
            assert metrics['cardGap'] is None or abs(metrics['cardGap']-20)<1,metrics
            assert all(abs(gap-8)<1 for gap in metrics['tips']),metrics
            assert not metrics['overflow'],metrics
            assert not _axe(page)
            if variant=='both':
                for tip in page.locator('.dashboard-sections .info-tip').all():
                    tip.focus()
                    assert tip.get_attribute('aria-label')
                    assert tip.evaluate("e=>getComputedStyle(e,'::after').display")!='none'
                out=Path('/private/tmp/serviceops-dashboard-spacing');out.mkdir(exist_ok=True)
                page.locator('h1').click()
                page.screenshot(path=str(out/f'{width}-{"dark" if dark else "light"}.png'),full_page=True)
            with app.app_context():
                if variant=='both':TaskSLA.query.filter_by(breached=True).delete()
                elif variant=='risk-only':
                    TaskSLA.query.update({TaskSLA.breached:True,TaskSLA.breach_at:now()-timedelta(hours=1)})
                else:TaskSLA.query.delete()
                db.session.commit()
        browser.close()
