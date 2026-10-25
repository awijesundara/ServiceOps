"""Cross-module layout audit and regression checks for shared interface geometry."""
import json
import os
from pathlib import Path
import pytest
from app import ConfigurationItem, Ticket, User, UserPreference, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_INTERFACE_SYSTEM_BROWSER')!='1',reason='opt-in interface audit')


@pytest.mark.parametrize('width,theme,compact,touch',[(1440,'light',False,False),(1280,'dark',True,False),(390,'light',False,True),(768,'dark',False,True)])
def test_interface_system(server,width,theme,compact,touch):
    from playwright.sync_api import sync_playwright
    app,base=server
    with app.app_context():
        admin=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme=theme;pref.density='compact' if compact else 'comfortable';db.session.add(pref)
        ci=ConfigurationItem(name='Interface audit CI',ci_class='Server',tenant_id=1)
        ticket=Ticket(number='INC990099',kind='incident',title='Interface audit incident',description='Synthetic record for layout checks',
                      state='New',priority='P3',category='Software',requester_id=admin.id,tenant_id=1)
        db.session.add_all([ci,ticket]);db.session.commit();ticket_id=ticket.id
    phase=os.getenv('INTERFACE_AUDIT_PHASE','after')
    output=Path('/private/tmp/serviceops-interface-'+phase);output.mkdir(parents=True,exist_ok=True)
    routes=['/','/tickets/incident','/tickets/new/incident',f'/ticket/{ticket_id}','/approval-chains','/catalog',
            '/service-operations/settings/service-offerings','/admin/users','/preferences','/knowledge','/cmdb',
            '/projects/WEB/board','/projects/WEB/backlog','/admin/interface-standards']
    results=[]
    with sync_playwright() as p:
        browser=p.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1100},has_touch=touch,is_mobile=touch,reduced_motion='reduce')
        errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
        _sign_in(page,base)
        for route in routes:
            response=page.goto(base+route,wait_until='networkidle');assert response.ok,(route,response.status)
            geometry=page.evaluate("""()=>{
              const visible=e=>e.checkVisibility()&&e.getBoundingClientRect().width>0;
              const box=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return {tag:e.tagName,cls:e.className,text:(e.textContent||e.getAttribute('placeholder')||'').trim().slice(0,60),x:Math.round(r.x),y:Math.round(r.y),w:Math.round(r.width),h:Math.round(r.height*10)/10,font:s.fontSize,pad:s.padding,gap:s.gap}};
              return {overflow:document.documentElement.scrollWidth>innerWidth+1,buttons:[...document.querySelectorAll('main button,main a.button,main a.primary')].filter(visible).map(box),
                actions:[...document.querySelectorAll('main .button,main .primary,main form>button:not([type=button]):not([class]),main .list-filter-toggle,main .columns-picker-toggle')].filter(visible).map(box),fields:[...document.querySelectorAll('main input:not([type=hidden]):not([type=checkbox]):not([type=radio]),main select')].filter(visible).map(box),
                panels:[...document.querySelectorAll('main .panel,main .list-workspace')].filter(visible).map(box),
                outside:[...document.querySelectorAll('main button,main input,main select,main textarea')].filter(e=>visible(e)&&e.getBoundingClientRect().right>innerWidth+1).map(box)};
            }""")
            results.append({'route':route,**geometry})
            slug=route.strip('/').replace('/','-') or 'home'
            if phase!='before':
                assert not geometry['overflow'],(route,geometry['outside'])
                expected=44 if touch else 34 if compact else 38
                assert all(abs(action['h']-expected)<1 for action in geometry['actions']),(route,expected,geometry['actions'])
                if route=='/tickets/new/incident':
                    assert page.locator('[data-similar-incidents]').bounding_box() is None
                    gap=page.locator('.record-long-fields').bounding_box()['y']-(page.locator('.record-grid').bounding_box()['y']+page.locator('.record-grid').bounding_box()['height'])
                    assert 0<=gap<=40,gap
                if route=='/service-operations/settings/service-offerings':
                    search=page.locator('.service-toolbar [name=q]').bounding_box()
                    action=page.locator('.service-toolbar button').bounding_box()
                    assert abs(search['height']-action['height'])<1
                    assert (abs((search['y']+search['height'])-(action['y']+action['height']))<1 if action['y'] < search['y']+search['height'] else abs(action['x']-search['x'])<1)
                    multi=page.locator('.lookup-multi').first.bounding_box()
                    assert abs(multi['height']-expected)<1,(multi,page.evaluate("({pointer:matchMedia('(pointer:coarse)').matches,control:getComputedStyle(document.body).getPropertyValue('--control-height')})"))
                frames=page.locator('main>.record-shell,main>.list-workspace')
                for frame in frames.all():
                    assert frame.evaluate('e=>Math.abs(e.getBoundingClientRect().left-(e.parentElement.getBoundingClientRect().left+parseFloat(getComputedStyle(e.parentElement).paddingLeft)))<1')
                violations=_axe(page)
                assert not violations,(route,violations)
            page.screenshot(path=str(output/f'{slug}-{width}-{theme}.png'),full_page=True)
        (output/f'audit-{width}-{theme}.json').write_text(json.dumps(results,indent=2))
        assert not errors,errors
        browser.close()
