"""Real browser regressions for authority assignment and same-page group saves."""
import os
import threading

import pytest
from werkzeug.serving import make_server

from app import db, GroupMember, SupportGroup, User
from tests.test_app import app  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv('RUN_ADMIN_ASSIGNMENT_BROWSER') != '1',
                               reason='RUN_ADMIN_ASSIGNMENT_BROWSER=1 enables real local browser checks')


@pytest.mark.parametrize('width,height', [(1440, 1000), (390, 844)])
def test_authority_and_group_assignment_browser(app, width, height):
    from playwright.sync_api import expect, sync_playwright

    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(viewport={'width':width,'height':height}, reduced_motion='reduce')
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(base+'/login')
            page.locator('input[name="username"]').fill('admin')
            page.locator('input[name="password"]').fill('Admin123!')
            page.locator('button.primary').click()
            page.wait_for_load_state('networkidle')
            page.goto(base+'/service-operations/settings/ccb')
            users = page.locator('[data-approval-users="ccb"]')
            picker = users.get_by_role('combobox', name='User to add')
            picker.fill('admin')
            picker.press('ArrowDown')
            picker.press('Enter')
            users.get_by_role('button', name='Add user').click()
            page.wait_for_load_state('networkidle')
            assert page.url.endswith('/settings/ccb')
            assert page.get_by_role('status').filter(has_text='CCB approval authority updated.').is_visible()
            assert users.locator('li').filter(has_text='admin').count() == 1
            users.locator('li').filter(has_text='admin').get_by_role('button').click()
            page.wait_for_load_state('networkidle')
            with app.app_context():
                uid = User.query.filter_by(username='admin').one().id
                gid = SupportGroup.query.filter_by(name='Change Control Board').one().id
                assert not GroupMember.query.filter_by(group_id=gid,user_id=uid,role='CCB approver').first()
                unix = SupportGroup.query.filter_by(name='Unix').one().id
            page.goto(base+'/service-operations/settings/governance-groups')
            panel = page.locator(f'#group-{unix}')
            panel.locator('summary').click()
            picker = panel.get_by_role('combobox', name='Add member to Unix')
            picker.fill('employee')
            picker.press('ArrowDown')
            picker.press('Enter')
            panel.get_by_role('button', name='Add member', exact=True).click()
            page.wait_for_load_state('networkidle')
            assert '/settings/governance-groups?' in page.url
            assert panel.get_attribute('open') is not None
            assert page.get_by_role('status').filter(has_text='added to Unix.').is_visible()
            expect(page.get_by_role('status').filter(has_text='added to Unix.')).to_be_in_viewport()
            for path in ['/service-operations/settings/ccb','/service-operations/settings/executive-approval']:
                page.goto(base+path)
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
                axe = os.getenv('AXE_CORE_PATH')
                assert axe and os.path.isfile(axe), 'AXE_CORE_PATH required for accessibility acceptance'
                # Inject via evaluate to exercise the unchanged production CSP.
                page.evaluate(open(axe, encoding='utf-8').read())
                violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
                assert not violations, [(v['id'],v['help']) for v in violations]
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
