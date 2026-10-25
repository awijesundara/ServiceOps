"""Requester home real-browser navigation, compact geometry and accessibility."""
import os
import threading
from pathlib import Path
from datetime import timedelta

import pytest
from werkzeug.serving import make_server
from app import CatalogItem, ChangeFreezeWindow, ServiceOffering, User, UserPreference, db, now
from tests.test_app import app  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_REQUESTER_HOME_BROWSER')!='1',reason='opt-in browser')


@pytest.mark.parametrize('width,theme,username',[(1440,'light','employee'),(390,'dark','employee'),(1440,'light','admin'),(390,'dark','admin'),(768,'dark','admin')])
def test_requester_home_browser(app,width,theme,username):
    from playwright.sync_api import sync_playwright, expect
    with app.app_context():
        employee=User.query.filter_by(username=username).one()
        pref=UserPreference.query.filter_by(user_id=employee.id).first() or UserPreference(user_id=employee.id)
        pref.theme=theme;db.session.add(pref)
        db.session.add(ServiceOffering(name='VPN & remote access',tenant_id=1,status='Degraded',status_page_visible=True))
        db.session.add(CatalogItem(name='Application access',category='Access',description='Request application access',tenant_id=1))
        for i,title in enumerate(('Quarter-end freeze','Month-end freeze','Maintenance freeze')):
            db.session.add(ChangeFreezeWindow(title=title,starts_at=now()+timedelta(days=2+i),ends_at=now()+timedelta(days=3+i),tenant_id=1))
        db.session.commit()
    app.config.update(CSRF_ENABLED=True,SESSION_COOKIE_SECURE=False)
    server=make_server('127.0.0.1',0,app,threaded=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch()
            page=browser.new_page(viewport={'width':width,'height':1100},has_touch=width<900,is_mobile=width<900,reduced_motion='reduce')
            errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
            base=f'http://127.0.0.1:{server.server_port}'
            page.goto(base+'/login');page.locator('[name=username]').fill(username)
            page.locator('[name=password]').fill('Employee123!' if username=='employee' else 'Admin123!');page.locator('button.primary').click()
            page.wait_for_load_state('networkidle')
            expect(page.locator('.portal-service-status')).to_contain_text('1 service affected')
            expect(page.locator('.requester-action')).to_have_count(3)
            assert page.locator('.portal-service-status').bounding_box()['height']<(145 if width<700 else 110)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1')
            expect(page.locator('[data-service-feed-pause]')).to_have_count(0)
            expect(page.locator('.service-feed button')).to_have_count(0)
            page.screenshot(path=f'/private/tmp/compact-home-{username}-{width}.png',full_page=width>=900)
            page.evaluate(Path(os.environ['AXE_CORE_PATH']).read_text())
            violations=page.evaluate("async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations,[(v['id'],v['nodes']) for v in violations]
            expect(page.locator('.portal-popular')).to_have_count(0)
            expect(page.get_by_role('link',name='Get access',exact=False)).to_have_count(0)
            feed=page.locator('.service-feed')
            position=feed.locator('[data-service-feed-position]')
            capacity=1
            def position_text(start):
                return f'{start} / 4'
            expect(feed.locator('[data-service-feed-item]:not([hidden])')).to_have_count(capacity)
            expect(feed.locator('[data-service-feed-controls]')).to_have_count(0)
            height=feed.bounding_box()['height']
            feed.locator('[data-service-feed-item]:not([hidden]) .service-headline').focus()
            page.keyboard.press('ArrowRight')
            expect(feed.locator('[data-service-feed-item]:not([hidden])').filter(has_text='Quarter-end freeze')).to_be_visible()
            assert abs(feed.bounding_box()['height']-height)<2
            page.screenshot(path=f'/private/tmp/service-feed-{username}-{width}.png',full_page=width>=900)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1')
            page.clock.install()
            page.clock.fast_forward(16000)
            expect(position).to_have_text(position_text(2))
            page.emulate_media(reduced_motion='no-preference')
            page.locator('h1').click();page.locator('h1').hover()
            page.clock.fast_forward(4100)
            expect(position).to_have_text(position_text(3))
            feed.hover();page.clock.fast_forward(16000)
            expect(position).to_have_text(position_text(3))
            page.locator('h1').hover();page.clock.fast_forward(4100)
            expect(position).to_have_text(position_text(4))
            feed.locator('[data-service-feed-item]:not([hidden]) .service-headline').focus();page.clock.fast_forward(16000)
            expect(position).to_have_text(position_text(4))
            page.keyboard.press('Space')
            page.locator('h1').click();page.locator('h1').hover();page.clock.fast_forward(16000)
            expect(position).to_have_text(position_text(4))
            page.locator('.portal-service-status header>a').click()
            expect(page.locator('h1')).to_have_text('Service status')
            page.wait_for_load_state('networkidle');page.clock.run_for(500)
            expect(page.locator('.service-notice-row').filter(has_text='Quarter-end freeze')).to_be_visible()
            page.evaluate(Path(os.environ['AXE_CORE_PATH']).read_text())
            detail_violations=page.evaluate("async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not detail_violations,[(v['id'],[(n['target'],n.get('failureSummary')) for n in v['nodes']]) for v in detail_violations]
            page.goto(base+'/');page.get_by_role('link',name='Request something',exact=False).click()
            expect(page.locator('.catalog-item').filter(has_text='Application access')).to_be_visible()
            page.goto(base+'/');page.get_by_role('link',name='Get help',exact=False).click()
            assert '/new/incident' in page.url or '/tickets/new' in page.url or '/ticket/new' in page.url,page.url
            if width==768:
                with app.app_context():
                    ChangeFreezeWindow.query.filter(ChangeFreezeWindow.title.in_(['Month-end freeze','Maintenance freeze'])).delete(synchronize_session=False)
                    db.session.commit()
                page.goto(base+'/',wait_until='networkidle')
                expect(page.locator('[data-service-feed-item]:not([hidden])')).to_have_count(1)
                expect(page.locator('[data-service-feed-controls]')).to_have_count(0)
                page.clock.fast_forward(16000)
                expect(page.locator('[data-service-feed-position]')).to_have_text('1 / 2')
                assert page.locator('.service-feed').bounding_box()['height']<=60
                with app.app_context():
                    ServiceOffering.query.filter_by(name='VPN & remote access').one().status='Operational'
                    ChangeFreezeWindow.query.filter_by(title='Quarter-end freeze').one().title='Quarter-end freeze — '+('important update '*8)
                    db.session.commit()
                page.goto(base+'/',wait_until='networkidle')
                expect(page.locator('[data-service-feed-item]:not([hidden])')).to_have_count(1)
                expect(page.locator('[data-service-feed-controls]')).to_have_count(0)
                headline=page.locator('.service-headline')
                assert len(headline.get_attribute('title'))>120
                assert headline.evaluate('e=>e.scrollWidth>e.clientWidth')
                assert page.locator('.service-feed').bounding_box()['height']<=60
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
                fallback=browser.new_context(java_script_enabled=False,storage_state=page.context.storage_state(),viewport={'width':768,'height':1100})
                fallback_page=fallback.new_page();fallback_page.goto(base+'/')
                expect(fallback_page.locator('.service-headline')).to_be_visible()
                assert fallback_page.locator('.service-feed').bounding_box()['height']<=60
                fallback.close()
                with app.app_context():
                    ChangeFreezeWindow.query.delete()
                    db.session.commit()
                page.goto(base+'/',wait_until='networkidle')
                expect(page.locator('.service-feed')).to_have_count(0)
                expect(page.locator('.service-feed-label')).to_have_count(0)
                expect(page.locator('[data-service-feed-controls]')).to_have_count(0)
                expect(page.locator('.portal-status-summary')).to_contain_text('All services operational')
                assert page.locator('.portal-service-status').bounding_box()['height']<70

            assert not errors,errors
            browser.close()
    finally:
        server.shutdown();thread.join(timeout=10)
