"""The eleven requested list routes share controls without losing domain actions."""
import json
import os
import tempfile
from pathlib import Path

import pytest

import app as core
from app import db
from serviceops_models import Contract, Supplier, ProblemProfile
from tests.test_app import app  # noqa: F401
from tests.test_projects_browser import server, _sign_in, _axe  # noqa: F401
from tests.test_sitewide_usability_browser import _seed

pytestmark = pytest.mark.skipif(os.getenv('RUN_UNIFIED_LISTS_BROWSER') != '1', reason='Opt-in unified list checks')
ROUTES = ['/work/tasks', '/requests', '/approval-chains', '/module/problem', '/known-errors', '/module/event',
          '/improvements', '/cmdb', '/assets', '/itam/suppliers', '/itam/contracts']


def seed(application):
    _seed(application)
    with application.app_context():
        admin = core.User.query.filter_by(username='admin').one()
        group = core.SupportGroup.query.filter_by(name='Unix').one()
        if not core.GroupMember.query.filter_by(user_id=admin.id, group_id=group.id).first():
            db.session.add(core.GroupMember(user_id=admin.id, group_id=group.id))
        incident = core.Ticket.query.filter_by(kind='incident').one()
        supplier = Supplier.query.first()
        for index in range(2):
            db.session.add(core.ConfigurationItem(name=f'Consistent list CI {index}', ci_class='Server', tenant_id=1))
            db.session.add(core.Asset(asset_tag=f'LIST-{index}', name=f'Consistent laptop {index}', asset_type='Laptop', tenant_id=1))
            db.session.add(Supplier(name=f'Consistent supplier {index}', tenant_id=1))
            db.session.add(Contract(name=f'Consistent contract {index}', supplier_id=supplier.id, tenant_id=1))
            db.session.add(core.CatalogRequest(number=f'REQ-LIST-{index}', requested_by_id=admin.id, requested_for_id=admin.id, tenant_id=1))
            db.session.add(core.ImprovementItem(number=f'IMP-LIST-{index}', title=f'Consistent improvement {index}', created_by_id=admin.id, tenant_id=1))
            for domain in ['problem', 'event']:
                config = core.DOMAIN_CONFIG[domain]
                record = core.EnterpriseRecord(number=f'{config["prefix"]}LIST{index}', domain=domain, record_type=config['types'][0],
                                               title=f'Consistent {domain} {index}', description='Synthetic list verification', requester_id=admin.id, tenant_id=1)
                db.session.add(record)
                db.session.flush()
                if domain == 'problem':
                    db.session.add(ProblemProfile(enterprise_record_id=record.id, known_error=True, root_cause='Synthetic cause', workaround='Synthetic workaround', tenant_id=1))
            for mine in [True, False]:
                db.session.add(core.OperationalTask(number=f'ITASK-LIST-{index}-{int(mine)}', task_kind='incident', parent_type='ticket',
                               parent_id=incident.id, title=f'Consistent task {index}', task_type='Investigation',
                               assignment_group_id=group.id, assignee_id=admin.id if mine else None, tenant_id=1))
        # Different targets exercise grouping and stripe parity.
        for index, target in enumerate(core.Ticket.query.all()):
            db.session.add(core.ApprovalChain(name=f'Consistent approval {index}', target_type='ticket', target_id=target.id, tenant_id=1))
        db.session.commit()


@pytest.mark.parametrize('width,theme', [(1440, 'light'), (390, 'light'), (1280, 'dark'), (390, 'midnight')])
def test_requested_lists_share_interface(server, width, theme):
    from playwright.sync_api import sync_playwright, expect
    application, base = server
    seed(application)
    with application.app_context():
        user = core.User.query.filter_by(username='admin').one()
        pref = core.UserPreference.query.filter_by(user_id=user.id).first() or core.UserPreference(user_id=user.id)
        pref.theme = theme
        db.session.add(pref)
        db.session.commit()
    output = Path(os.getenv('SERVICEOPS_UI_ARTIFACT_ROOT', tempfile.gettempdir())) / 'unified-record-lists'
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={'width': width, 'height': 1100}, has_touch=width < 900, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        _sign_in(page, base)
        for route in ROUTES:
            response = page.goto(base + route, wait_until='networkidle')
            assert response.ok, (route, response.status)
            workspaces = page.locator('main .list-workspace')
            assert workspaces.count() >= 1, route
            for workspace in workspaces.all():
                menu = workspace.locator('.list-title .list-filter-toggle')
                expect(menu).to_have_count(1)
                expect(workspace.locator('.list-search .list-filter-toggle')).to_have_count(0)
                expect(workspace.locator('a[data-list-all]')).to_have_count(1)
                rows = workspace.locator('table.record-list-table>tbody>tr:not(.approval-history-row)')
                assert rows.count() >= 2, (route, rows.count())
                page.mouse.move(0, 0)
                colors = rows.evaluate_all('rows=>rows.map(r=>getComputedStyle(r).backgroundColor)')
                assert colors[0] != colors[1], (route, colors)
                menu.focus()
                menu.press('Enter')
                editor = workspace.locator('.list-filter-builder')
                expect(editor).to_be_visible()
                expect(menu).to_have_attribute('aria-expanded', 'true')
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'), route
                assert not _axe(page), route
                page.emulate_media(media='print')
                expect(editor).to_be_hidden()
                page.emulate_media(media='screen')
                expect(editor).to_be_visible()
                page.keyboard.press('Escape')
                expect(menu).to_be_focused()
                expect(editor).to_be_hidden()
            assert not _axe(page), route
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1'), route
            page.screenshot(path=str(output/f'{route.strip("/").replace("/", "-")}-{width}-{theme}.png'), full_page=True)
            # Submit actual server filters, including native query mirrors.
            workspace = workspaces.first
            workspace.locator('.list-filter-toggle').click()
            editor = workspace.locator('.list-filter-builder')
            mirror = editor.locator('[data-list-query]')
            if mirror.count():
                mirror.fill('No matching record for this unified list query')
                mirror.press('Enter')
            else:
                row = editor.locator('.filter-row').first
                fields = json.loads(workspace.locator('[data-filter-fields]').get_attribute('data-filter-fields'))
                text_key = next(key for key, value in fields.items() if value.get('type', 'text') == 'text')
                row.locator('.filter-field').select_option(text_key)
                row.locator('.filter-op').select_option('contains')
                row.locator('.filter-value').fill('No matching record for this unified list query')
                editor.get_by_role('button', name='Run', exact=True).click()
            page.wait_for_load_state('networkidle')
            for table in page.locator('table.record-list-table').all():
                expect(table.locator(':scope>tbody>tr>td:is(.empty,.empty-table)')).to_have_count(1)
            page.locator('a[data-list-all]').first.click()
            page.wait_for_load_state('networkidle')
            assert page.locator('table.record-list-table>tbody>tr:not(.approval-history-row)').count() >= 2
            assert 'No+matching' not in page.url and 'No%20matching' not in page.url
            results.append({'route': route, 'width': width, 'theme': theme, 'passed': True})
        assert not errors, errors
        (output/f'results-{width}-{theme}.json').write_text(json.dumps(results, indent=2))
        browser.close()
