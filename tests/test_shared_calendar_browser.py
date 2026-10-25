"""One reusable calendar across real range forms, single fields and dynamic inputs."""
import os
from pathlib import Path
import pytest
from app import ChangeFreezeWindow, User, UserPreference, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401

pytestmark=pytest.mark.skipif(os.getenv('RUN_INTERFACE_SYSTEM_BROWSER')!='1',reason='opt-in shared calendar')


def select_month(dialog,year,month):
    dialog.get_by_label('Year',exact=True).fill(str(year))
    dialog.get_by_label('Year',exact=True).press('Tab')
    dialog.get_by_label('Month',exact=True).select_option(str(month-1))


def choose(dialog,value):
    dialog.locator(f'[data-calendar-date="{value}"]').click()


@pytest.mark.parametrize('width,dark,touch',[(1440,False,False),(1280,True,False),(390,False,True),(768,True,True)])
def test_shared_calendar_real_save_and_constraints(server,width,dark,touch):
    from playwright.sync_api import sync_playwright,expect
    app,base=server
    with app.app_context():
        admin=User.query.filter_by(username='admin').one()
        pref=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        pref.theme='dark' if dark else 'light';pref.timezone='Asia/Tokyo';db.session.add(pref);db.session.commit()
    app.config.update(CSRF_ENABLED=True,SESSION_COOKIE_SECURE=False)
    with sync_playwright() as p:
        browser=p.chromium.launch()
        page=browser.new_page(viewport={'width':width,'height':1000},has_touch=touch,is_mobile=touch)
        errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
        _sign_in(page,base)
        page.goto(base+'/service-operations/settings/change-freeze',wait_until='networkidle')
        window=page.get_by_role('button',name='Choose date window',exact=True)
        expect(window).to_have_count(1);window.click()
        dialog=page.get_by_role('dialog',name='Choose date window',exact=True)
        select_month(dialog,2028,2)
        choose(dialog,'2028-02-29')
        dialog.get_by_role('button',name='Next month',exact=True).click()
        choose(dialog,'2028-03-02')
        dialog.get_by_label('Start time',exact=True).fill('10:15')
        dialog.get_by_label('End time',exact=True).fill('18:30')
        assert not _axe(page)
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        out=Path('/private/tmp/serviceops-calendar');out.mkdir(exist_ok=True)
        page.screenshot(path=str(out/f'range-{width}-{"dark" if dark else "light"}.png'),full_page=True)
        dialog.get_by_role('button',name='Apply dates',exact=True).click()
        expect(page.locator('[name=starts_at]')).to_have_value('2028-02-29T10:15')
        expect(page.locator('[name=ends_at]')).to_have_value('2028-03-02T18:30')
        # Escape/cancel makes no partial edits and returns keyboard focus.
        window.click();select_month(dialog,2028,4);choose(dialog,'2028-04-01');choose(dialog,'2028-04-01')
        dialog.get_by_label('Start time',exact=True).fill('12:00');dialog.get_by_label('End time',exact=True).fill('10:00')
        dialog.get_by_role('button',name='Apply dates',exact=True).click()
        expect(dialog.get_by_role('alert')).to_contain_text('The end must be on or after the start.')
        expect(page.locator('[name=starts_at]')).to_have_value('2028-02-29T10:15')
        dialog.get_by_role('button',name='Clear dates',exact=True).click();dialog.get_by_role('button',name='Apply dates',exact=True).click()
        expect(dialog.get_by_role('alert')).to_contain_text('These dates are required.')
        page.keyboard.press('Escape')
        expect(page.locator('[name=starts_at]')).to_have_value('2028-02-29T10:15')
        expect(window).to_be_focused()
        page.locator('input[name=title]').fill('Calendar saved freeze')
        page.get_by_role('button',name='Create freeze window',exact=True).click();page.wait_for_load_state('networkidle')
        with app.app_context():
            freeze=ChangeFreezeWindow.query.filter_by(title='Calendar saved freeze').one()
            assert freeze.starts_at.isoformat().startswith('2028-02-29T01:15')
            assert freeze.ends_at.isoformat().startswith('2028-03-02T09:30')
        # Shared reference: native bounds, reverse selection, same-day ranges and single-date keyboard use.
        page.goto(base+'/admin/interface-standards',wait_until='networkidle')
        page.get_by_role('button',name='Choose date window',exact=True).click()
        dialog=page.get_by_role('dialog',name='Choose date window',exact=True)
        select_month(dialog,2019,12)
        expect(dialog.locator('[data-calendar-date="2019-12-31"]')).to_be_disabled()
        select_month(dialog,2028,3);choose(dialog,'2028-03-20');choose(dialog,'2028-03-10')
        dialog.get_by_role('button',name='Apply dates',exact=True).click()
        expect(page.locator('[name=start_date]')).to_have_value('2028-03-10')
        expect(page.locator('[name=due_date]')).to_have_value('2028-03-20')
        page.get_by_role('button',name='Choose date window',exact=True).click()
        choose(dialog,'2028-03-15');choose(dialog,'2028-03-15')
        dialog.get_by_role('button',name='Apply dates',exact=True).click()
        expect(page.locator('[name=due_date]')).to_have_value('2028-03-15')
        page.locator('[name=sample_date]').click()
        single=page.get_by_role('dialog',name='Choose date',exact=True)
        select_month(single,2028,2)
        day=single.locator('[data-calendar-date="2028-02-28"]');day.focus();day.press('ArrowRight')
        expect(single.locator('[data-calendar-date="2028-02-29"]')).to_be_focused()
        page.keyboard.press('PageDown');expect(single.locator('[data-calendar-date="2028-03-29"]')).to_be_focused()
        single.locator('[data-calendar-date="2028-03-31"]').focus();page.keyboard.press('PageUp')
        expect(single.locator('[data-calendar-date="2028-02-29"]')).to_be_focused()
        page.keyboard.press('Shift+PageDown');expect(single.locator('[data-calendar-date="2029-02-28"]')).to_be_focused()
        select_month(single,2028,2);single.locator('[data-calendar-date="2028-02-29"]').focus()
        page.keyboard.press('Enter');single.get_by_role('button',name='Apply dates',exact=True).click()
        expect(page.locator('[name=sample_date]')).to_have_value('2028-02-29')
        # Dynamic filters get the same behavior; unrelated date fields never pair.
        page.evaluate("""()=>{const l=document.createElement('label');l.textContent='Dynamic date';const i=document.createElement('input');i.type='date';i.name='dynamic_date';l.append(i);document.querySelector('main').append(l)}""")
        dynamic=page.locator('[name=dynamic_date]');expect(dynamic).to_have_attribute('data-calendar-ready',__import__('re').compile(r'\d+'))
        dynamic.focus();dynamic.press('Alt+ArrowDown');expect(page.get_by_role('dialog',name='Choose date',exact=True)).to_be_visible()
        page.keyboard.press('Escape')
        assert not _axe(page)
        if width==1440:
            page.evaluate("()=>{document.querySelector('#ui-calendar').showModal=()=>{throw new TypeError('calendar test failure')};}")
            dynamic.click()
            expect(page.get_by_role('alert')).to_contain_text('The calendar is unavailable.')
            expect(dynamic).not_to_have_class(__import__('re').compile('ui-date-input'))
            dynamic.fill('2028-04-01');expect(dynamic).to_have_value('2028-04-01')
        assert not errors,errors
        browser.close()


def test_range_coverage_across_existing_forms(server,tmp_path,monkeypatch):
    from playwright.sync_api import sync_playwright,expect
    _,base=server
    log_dir=tmp_path/'logs';log_dir.mkdir();(log_dir/'serviceops.json.log').write_text('')
    monkeypatch.setenv('LOG_DIR',str(log_dir))
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':1440,'height':1000})
        _sign_in(page,base)
        for route,start,end in [('/tickets/new/change','planned_start','planned_end'),
                ('/service-operations/settings/change-freeze','starts_at','ends_at'),
                ('/projects/WEB/backlog','start_at','end_at'),('/projects/WEB/releases','start_date','release_date'),
                ('/projects/WEB/items/new','start_date','due_date'),('/itam/contracts/new','start_date','end_date'),
                ('/admin/system-health','from','to'),('/admin/system-health/logs','from','to')]:
            response=page.goto(base+route,wait_until='networkidle');assert response.ok,(route,response.status)
            field=page.locator(f'input[name="{start}"]').first
            expect(field).to_have_attribute('data-calendar-ready',__import__('re').compile(r'\d+'))
            expect(page.locator(f'input[name="{end}"]').first).to_have_attribute('data-calendar-ready',__import__('re').compile(r'\d+'))
            assert page.locator('.ui-date-window').count()>=1,route
        browser.close()
