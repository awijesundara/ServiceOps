"""Ticket striping, toolbar filter keyboard behavior and actual print trigger."""
import os
import tempfile
from pathlib import Path

import pytest

from app import Ticket, User, UserPreference, db
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv('RUN_PROJECTS_BROWSER') != '1', reason='Opt-in browser checks')


@pytest.mark.parametrize('width,theme', [(1440, 'light'), (390, 'light'), (1440, 'dark'), (390, 'midnight')])
def test_ticket_list_controls(server, width, theme):
    from playwright.sync_api import expect, sync_playwright
    application, base = server
    with application.app_context():
        user = User.query.filter_by(username='admin').one()
        pref = UserPreference.query.filter_by(user_id=user.id).first() or UserPreference(user_id=user.id)
        pref.theme = theme
        db.session.add(pref)
        for kind, prefix in [('incident', 'INC'), ('change', 'CHG')]:
            for index in range(3):
                db.session.add(Ticket(number=f'{prefix}99008{index}', kind=kind, title=f'List striping {kind} {index}',
                                      description='Isolated UI fixture', state='Cancelled' if index == 2 else 'New',
                                      priority='P3', category='Software', requester_id=user.id, tenant_id=user.tenant_id))
        db.session.commit()
    output = Path(os.getenv('SERVICEOPS_UI_ARTIFACT_ROOT', tempfile.gettempdir())) / 'serviceops-ticket-lists'
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={'width': width, 'height': 1050}, has_touch=width < 900, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        _sign_in(page, base)
        for kind in ['incident', 'change', 'all']:
            page.goto(base + '/tickets/' + kind + '?filter=[]', wait_until='networkidle')
            page.mouse.move(0, 0)
            rows = page.locator('.ticket-list-table tbody tr')
            colors = rows.evaluate_all('rows=>rows.map(row=>getComputedStyle(row).backgroundColor)')
            assert colors[0] != colors[1] and colors[0] == colors[2], colors
            assert page.locator('.status-row-inactive td').first.evaluate('e=>getComputedStyle(e).fontStyle') == 'italic'
            menu = page.get_by_role('button', name='Open ticket filters', exact=True)
            editor = page.locator('.list-filter-builder')
            expect(page.locator('.list-filter-toggle')).to_have_count(1)
            expect(page.locator('#ticket-list-search .list-filter-toggle')).to_have_count(0)
            assert menu.locator('svg path').get_attribute('d').startswith('M3 4h18')
            assert menu.bounding_box()['x'] < page.locator('.list-title strong').bounding_box()['x']
            menu.focus()
            menu.press('Enter')
            expect(editor).to_be_visible()
            expect(menu).to_have_attribute('aria-expanded', 'true')
            expect(editor.locator('.filter-field')).to_be_focused()
            assert not _axe(page)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            page.keyboard.press('Escape')
            expect(menu).to_be_focused()
            expect(editor).to_be_hidden()
            menu.click()
            row = editor.locator('.filter-row').first
            row.locator('.filter-field').select_option('title')
            row.locator('.filter-op').select_option('contains')
            row.locator('.filter-value').fill('List striping')
            editor.get_by_role('button', name='Run', exact=True).click()
            page.wait_for_load_state('networkidle')
            assert 'filter=' in page.url
            expect(page.locator('.list-breadcrumb')).to_contain_text('List striping')
            expect(page.locator('.ticket-list-table tbody')).to_contain_text('List striping')
            menu.click()
            page.locator('.list-title strong').click()
            expect(editor).to_be_hidden()
            expect(menu).to_have_attribute('aria-expanded', 'false')
            if width > 900:
                page.evaluate('() => {window.printCalls=0;window.print=()=>{window.printCalls++;};}')
                print_button = page.get_by_role('button', name='Print', exact=True)
                expect(print_button.locator('svg')).to_have_count(1)
                print_button.click()
                assert page.evaluate('window.printCalls') == 1
                assert '🖶' not in print_button.inner_text()
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            assert not _axe(page)
            page.screenshot(path=str(output/f'{kind}-{width}-{theme}.png'), full_page=True)
            menu.click()
            editor.get_by_role('button', name='Clear filter', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(editor).to_be_hidden()
            menu.click()
            row = editor.locator('.filter-row').first
            row.locator('.filter-field').select_option('title')
            row.locator('.filter-op').select_option('contains')
            row.locator('.filter-value').fill('nothing matches this ticket search')
            row.locator('.filter-value').press('Enter')
            page.wait_for_load_state('networkidle')
            expect(page.locator('.ticket-list-table .empty')).to_be_visible()
            menu.click()
            editor.get_by_role('button', name='Clear filter', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(page.locator('.status-row-inactive')).not_to_have_count(0)
            menu.click()
            row = editor.locator('.filter-row').first
            row.locator('.filter-field').select_option('title')
            row.locator('.filter-op').select_option('contains')
            row.locator('.filter-value').fill('nothing matches this ticket search')
            row.locator('.filter-value').press('Enter')
            page.wait_for_load_state('networkidle')
            search = page.locator('#ticket-list-search [name=q]')
            search.fill('also unmatched')
            search.press('Enter')
            page.wait_for_load_state('networkidle')
            all_link = page.locator('.ticket-all-link')
            all_link.focus()
            all_link.press('Enter')
            page.wait_for_load_state('networkidle')
            expect(page.locator('.status-row-inactive')).not_to_have_count(0)
            expect(page.locator('#ticket-list-search [name=q]')).to_have_value('')
            assert page.url.endswith('/tickets/' + kind + '?filter=%5B%5D'), page.url
        assert not errors
        browser.close()
