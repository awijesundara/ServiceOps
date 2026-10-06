"""Executive membership and concise settings controls."""
import os

import pytest

from app import (Audit, ChangeGovernance, ChangeOwnership, ConfigurationItem, GroupMember, PlatformSetting,
                 SupportGroup, Ticket, User, change_approval_stages, client_sysops_group, db,
                 resolve_support_group_by_name)
from tests.test_app import app, client, login  # noqa: F401


@pytest.mark.parametrize("mode", ["all", "any"])
def test_multiple_executive_approvers_can_be_saved(app, client, mode):
    login(client)
    with app.app_context():
        users = User.query.filter(User.username.in_(["admin", "employee"])).all()
        ids = [user.id for user in users]
    response = client.post('/itil/administration', data={"action": "set_executive_approvers", "user_ids": ids, "approval_mode": mode})
    assert response.status_code == 302
    with app.app_context():
        executive = SupportGroup.query.filter_by(name="Executive Office").one()
        assert executive.manager_id is None and executive.approval_mode == mode
        assert {member.user_id for member in executive.members if member.role == "executive approver"} == set(ids)
    page = client.get('/service-operations/settings/executive-approval').get_data(as_text=True)
    assert 'name="user_ids"' in page and 'name="approval_mode"' in page


@pytest.mark.parametrize("ids,mode", [(["not-an-id"], "all"), (["99999999"], "all"), ([], "invalid")])
def test_invalid_executive_selection_preserves_current_authority(app, client, ids, mode):
    login(client)
    with app.app_context():
        previous = SupportGroup.query.filter_by(name="Executive Office").one().manager_id
    response = client.post('/itil/administration', data={"action": "set_executive_approvers", "user_ids": ids, "approval_mode": mode})
    assert response.status_code == 400
    with app.app_context():
        assert SupportGroup.query.filter_by(name="Executive Office").one().manager_id == previous


def test_non_admin_cannot_change_executive_authority(client):
    login(client, 'employee', 'Employee123!')
    assert client.post('/itil/administration', data={"action": "set_executive_approvers", "approval_mode": "any"}).status_code == 403


def test_executive_replacement_removes_old_approval_authority(app, client):
    login(client)
    with app.app_context():
        employee_id = User.query.filter_by(username="employee").one().id
    assert client.post('/itil/administration', data={"action": "set_executive_approvers", "user_ids": [employee_id], "approval_mode": "any"}).status_code == 302
    assert client.post('/itil/administration', data={"action": "set_executive_approvers", "user_ids": [], "approval_mode": "all"}).status_code == 302
    with app.app_context():
        group = SupportGroup.query.filter_by(name="Executive Office").one()
        assert group.manager_id is None
        assert not GroupMember.query.filter_by(group_id=group.id, role="executive approver").all()


def test_requested_verbose_copy_is_removed(client):
    login(client)
    roles = client.get('/admin/roles').get_data(as_text=True)
    assert 'Git-backed, ITIL-recommended baseline' not in roles
    health = client.get('/admin/system-health').get_data(as_text=True)
    assert 'About this page' not in health and 'volume would dwarf' not in health


@pytest.mark.parametrize("name", ["Unix", "SysOps"])
def test_renaming_keeps_record_links_and_old_name_resolution(app, client, name):
    login(client)
    with app.app_context():
        group = SupportGroup.query.filter_by(name=name, tenant_id=1).one()
        gid, group_type = group.id, group.group_type
        ci = ConfigurationItem(name='rename-test', ci_class='Server', support_group_id=gid, tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id = ci.id
    renamed = name + ' operations'
    assert client.post(f'/admin/groups/{gid}', data={"name": renamed, "group_type": group_type, "active": "on"}).status_code == 302
    with app.app_context():
        group = db.session.get(SupportGroup, gid)
        assert group.active and group.name == renamed
        assert db.session.get(ConfigurationItem, ci_id).support_group.name == renamed
        assert resolve_support_group_by_name(name, 1).id == gid
        assert Audit.query.filter_by(action='team renamed', target=f'support_group:{gid}').one().details == f'{name} → {renamed}'
        if name == 'SysOps':
            assert client_sysops_group(1).id == gid


@pytest.mark.parametrize("mode", ["any", "all"])
def test_executive_stage_uses_all_selected_active_users(app, client, mode):
    login(client)
    with app.app_context():
        users = User.query.filter(User.username.in_(['admin', 'employee'])).all()
        ids = [user.id for user in users]
    assert client.post('/itil/administration', data={"action": "set_executive_approvers", "user_ids": ids, "approval_mode": mode}).status_code == 302
    with app.app_context():
        manager = User.query.filter_by(username='database.manager').one()
        group = SupportGroup.query.filter_by(name='Windows').one()
        ticket = Ticket(number='CHG-EXEC-MULTI', kind='change', title='Test executive quorum', description='Review', requester_id=manager.id)
        db.session.add(ticket)
        db.session.flush()
        db.session.add_all([ChangeOwnership(ticket_id=ticket.id, group_id=group.id),
                            ChangeGovernance(ticket_id=ticket.id, change_type='Normal', risk_score=40, impact='Medium',
                                             implementation_plan='Apply', test_plan='Check', backout_plan='Restore')])
        db.session.commit()
        stage = change_approval_stages(ticket)[-1]
        assert stage['name'] == 'Executive (CEO) approval' and stage['mode'] == mode
        assert stage['approver_ids'] == sorted(ids)
        db.session.get(User, ids[-1]).active = False
        db.session.commit()
        assert change_approval_stages(ticket)[-1]['approver_ids'] == [ids[0]]


def test_invalid_syslog_destination_does_not_save_settings(app, client):
    login(client)
    response = client.post('/admin/settings/security', data={'SYSLOG_ENABLED': 'on', 'SYSLOG_HOST': 'https://bad-host',
                                                           'SYSLOG_PORT': '514', 'SYSLOG_TRANSPORT': 'tcp'})
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(PlatformSetting, 'SYSLOG_ENABLED') is None


def _require_browser_tooling():
    """Skip where the browser job's tooling is absent (e.g. the Docker test image)."""
    pytest.importorskip("playwright.sync_api")
    if not os.path.isfile(os.environ.get("AXE_CORE_PATH", "")):
        pytest.skip("AXE_CORE_PATH must point to axe.min.js for browser accessibility checks")


@pytest.mark.parametrize('width', [1440, 390])
def test_browser_admin_controls_are_accessible_and_save_multiple_executives(app, client, width):
    _require_browser_tooling()
    import os
    import threading
    from pathlib import Path
    from playwright.sync_api import sync_playwright
    from werkzeug.serving import make_server

    login(client)
    with app.app_context():
        selected = [user.id for user in User.query.filter(User.username.in_(['admin', 'employee'])).all()]
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            context = browser.new_context(viewport={'width': width, 'height': 1000}, reduced_motion='reduce')
            context.add_cookies([{'name': 'session', 'value': client.get_cookie('session').value, 'domain': '127.0.0.1', 'path': '/'}])
            page = context.new_page()
            base = f'http://127.0.0.1:{server.server_port}'
            for path in ['/admin/roles', '/admin/system-health', '/admin/settings/security',
                         '/service-operations/settings/team-managers', '/service-operations/settings/governance-groups',
                         '/service-operations/settings/executive-approval']:
                page.goto(base + path, wait_until='networkidle')
                page.evaluate(Path(os.environ['AXE_CORE_PATH']).read_text())
                violations = page.evaluate("async () => (await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa']}})).violations")
                assert not violations, (path, [(item['id'], [node['target'] for node in item['nodes']]) for item in violations])
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), path
            for checkbox in page.locator('input[name="user_ids"]').all():
                checkbox.uncheck()
            for user_id in selected:
                page.locator(f'input[name="user_ids"][value="{user_id}"]').check()
            page.get_by_label('Approval rule').select_option('any')
            page.get_by_role('button', name='Save executive approvers').click()
            page.wait_for_load_state('networkidle')
            with app.app_context():
                executive = SupportGroup.query.filter_by(name='Executive Office').one()
                assert executive.approval_mode == 'any'
                assert {member.user_id for member in executive.members if member.role == 'executive approver'} == set(selected)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
