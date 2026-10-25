"""Exercise the service creation form with real JavaScript, CSRF and accessibility."""
import os
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server
from app import ConfigurationItem, ServiceOffering, ServiceOfferingCI, Ticket, User, UserPreference, db
from tests.test_app import group_id
from tests.test_app import app  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv('RUN_SERVICE_OFFERING_BROWSER') != '1', reason='opt-in browser acceptance')


@pytest.mark.parametrize('width,theme', [(1440, 'light'), (390, 'dark')])
def test_create_service_browser(app, width, theme):
    from playwright.sync_api import sync_playwright, expect
    with app.app_context():
        owner = User.query.filter_by(username='admin').one()
        preference = UserPreference.query.filter_by(user_id=owner.id).first()
        if preference is None:
            preference = UserPreference(user_id=owner.id)
            db.session.add(preference)
        preference.theme = theme
        ci = ConfigurationItem(name='Browser payment database', ci_class='Server', tenant_id=owner.tenant_id)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={'width': width, 'height': 1000}, color_scheme=theme)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + '/login')
            page.locator('[name=username]').fill('admin')
            page.locator('[name=password]').fill('Admin123!')
            page.locator('button.primary').click()
            page.wait_for_load_state('networkidle')
            page.goto(base + '/service-operations/settings/service-offerings')
            assert page.locator('html').evaluate("element => element.classList.contains('theme-dark')") == (theme == 'dark')
            page.get_by_label('Service name', exact=True).fill('Browser Payments')
            picker = page.get_by_role('combobox', name='Owning team')
            picker.fill('Unix')
            picker.press('ArrowDown')
            picker.press('Enter')
            creation = page.locator('#new-service')
            creation.locator('.lookup-search').fill('Browser payment database')
            creation.locator('.lookup-results').get_by_text('Browser payment database', exact=False).first.click()
            expect(creation.locator('input[name=ci_id]')).to_have_count(1)
            page.get_by_role('button', name='Create service offering', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(page.get_by_role('status').filter(has_text='Service Browser Payments saved.')).to_be_visible()
            assert '/service-operations/settings/service-offerings?service=' in page.url
            expect(page.locator('article').filter(has_text='Browser Payments')).to_be_visible()
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            axe = Path(os.environ['AXE_CORE_PATH'])
            page.evaluate(axe.read_text())
            violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations, [(v['id'], v['help']) for v in violations]
            # Use the browser's service card to map its CI, then create a change
            # through the authenticated web form endpoint with the same CSRF policy.
            card = page.locator('article').filter(has_text='Browser Payments')
            with app.app_context():
                assert ServiceOfferingCI.query.count() == 1
            card.get_by_label('Service name', exact=True).fill('Browser Payments revised')
            card.get_by_label('Criticality', exact=True).select_option('High')
            card.get_by_role('button', name='Save service details', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(card.locator('details.service-editor')).to_have_attribute('open', '')
            expect(card).to_contain_text('Browser payment database')
            page.screenshot(path=f'/private/tmp/service-ux-{width}.png', full_page=True)

            card.locator('.lookup-search').fill('Browser payment database')
            card.locator('.lookup-results').get_by_text('Browser payment database', exact=False).first.click()
            card.get_by_role('button', name='Link CIs', exact=True).click()
            page.wait_for_load_state('networkidle')
            card.get_by_label('Relationship for Browser payment database', exact=True).select_option('Primary')
            card.get_by_role('button', name='Save role', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(card.locator('details.service-editor')).to_have_attribute('open', '')

            token = page.locator('meta[name="csrf-token"]').get_attribute('content')
            response = page.request.post(base + '/tickets/new/change', form={
                'title': 'Browser payment change', 'description': 'Maintenance', 'category': 'Software',
                'priority': 'P3', 'change_type': 'Standard', 'risk_score': '20', 'impact': 'Low',
                'group_id': group_id(app, 'Unix'), 'implementation_plan': 'Implement',
                'test_plan': 'Verify', 'backout_plan': 'Restore', 'ci_id': str(ci_id),
                'planned_start': '2026-12-01T09:00', 'planned_end': '2026-12-01T10:00',
            }, headers={'X-CSRF-Token': token}, max_redirects=0)
            assert response.status == 302
            with app.app_context():
                tid = Ticket.query.filter_by(title='Browser payment change').one().id
            page.goto(base + f'/ticket/{tid}')
            page.locator('a[href="#gov-impacted-services"]').click()
            impact = page.locator('#gov-impacted-services')
            expect(page.locator('a[href="#gov-impacted-services"]')).to_contain_text('1 services, 0 manual CIs')
            expect(impact.locator('[data-impacted-service]')).to_contain_text('Browser Payments')
            expect(impact.locator('[data-impacted-service]')).to_contain_text('Browser payment database')
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            page.evaluate(axe.read_text())
            violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations, [(v['id'], v['help']) for v in violations]
            # Remove the mapping through the same editor users operate.
            with app.app_context():
                service_id = ServiceOffering.query.filter_by(name='Browser Payments revised').one().id
            page.goto(base + f'/service-operations/settings/service-offerings?service={service_id}')
            card.get_by_role('button', name='Unlink Browser payment database', exact=True).click()
            page.wait_for_load_state('networkidle')
            expect(card.locator('details.service-editor')).to_have_attribute('open', '')
            expect(card.locator('summary').first).to_contain_text('CIs: 0')
            page.goto(base + f'/ticket/{tid}')
            page.locator('a[href="#gov-impacted-services"]').click()
            expect(impact.locator('[data-impacted-service]')).to_have_count(0)
            expect(page.locator('a[href="#gov-impacted-services"]')).to_contain_text('0 services, 0 manual CIs')
            expect(impact).to_contain_text('No service offerings mapped')
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
