"""Complete draft transfer, timezone conversion, references and review-only creation."""
import json
import re
import uuid

from app import ConfigurationItem, SupportGroup, Ticket, db
from serviceops_core.ai import access, service
from serviceops_core.ai.ticket_drafts import bind_draft, form_values
from tests.test_ai_context import app, client, world, chat_ready, login  # noqa: F401
from tests.test_ai_privacy import scope_for


def draft_fields():
    return {'kind': 'change', 'title': 'Upgrade SAMPLE server', 'description': 'OS upgrade. ' * 400,
            'impact': 'Medium', 'urgency': 'Medium', 'change_type': 'Normal',
            'planned_start': '2030-11-02T08:00:00+09:00', 'planned_end': '2030-11-02T09:00:00+09:00',
            'implementation_plan': 'Verify compatibility and a restorable backup. Upgrade during the approved window. ' * 30,
            'test_plan': 'Verify boot, networking and application health. Stop on failed checks.',
            'backout_plan': 'Restore the verified backup if the upgrade or health checks fail.'}


def test_complete_change_draft_transfers_all_fields_and_creates_only_after_review(app, client, world, chat_ready, monkeypatch):
    with app.app_context():
        team = SupportGroup.query.filter_by(name='Database').one()
        ci = ConfigurationItem(name='SAMPLE server', ci_class='Server', support_group_id=team.id, tenant_id=1)
        db.session.add(ci)
        db.session.commit()
        ci_id, team_id = ci.id, team.id
        before = Ticket.query.count()

    def generated(config, messages, on_delta, thinking=None):
        records, _ = json.JSONDecoder().raw_decode(messages[-1]['content'].split('\n', 1)[1])
        source = next(row['source'] for row in records['records'] if row.get('kind') == 'ci' and row['title'] == 'SAMPLE server')
        fields = draft_fields()
        fields['ci_sources'] = [source]
        answer = 'Review the draft before submitting.\n[[TICKET]] ' + json.dumps(fields)
        on_delta('content', answer)
        return answer, '', {}

    monkeypatch.setattr(service, 'generate_stream', generated)
    login(client)
    reply = client.post('/ai/chat/messages', json={'text': 'create a new change for SAMPLE server OS upgrade, fill all the fields for review',
                                                  'request_key': str(uuid.uuid4())}).get_json()
    with app.app_context():
        while service.process_one():
            pass
    body = client.get(f"/ai/chat/conversations/{reply['conversation_id']}").get_json()['messages'][1]
    assert body['status'] == 'completed', body
    draft = body['route']['draft']
    assert draft['missing_fields'] == []
    assert draft['ci_ids'] == [ci_id] and draft['group_id'] == team_id
    assert len(draft['url']) < 200 and 'draft_run=' in draft['url']
    assert draft['planned_start'] == '2030-11-01T23:00'
    assert draft['planned_end'] == '2030-11-02T00:00'
    page = client.get(draft['url'] + '&planned_start=1999-01-01T00:00').get_data(as_text=True)
    for key in ('title', 'description', 'implementation_plan', 'test_plan', 'backout_plan'):
        assert draft_fields()[key].strip() in page
    assert 'name="planned_start" required value="2030-11-01T23:00"' in page
    assert 'Planned start (UTC)' in page
    assert f'value="{team_id}"' in page and 'SAMPLE server' in page
    with app.app_context():
        assert Ticket.query.count() == before
        values = form_values(draft, scope_for(world.admin).identity,
                             [{'id': draft['ci_sources'][0], 'kind': 'ci', 'record_id': ci_id}])
    created = client.post('/tickets/new/change', data=values)
    assert created.status_code == 302
    with app.app_context():
        saved = Ticket.query.filter_by(title=draft['title']).one()
        assert saved.change_governance.ci_id == ci_id
        assert saved.change_governance.planned_start.hour == 23
        assert saved.change_governance.implementation_plan == draft['implementation_plan']
    login(client, 'employee', 'Employee123!')
    assert client.get(draft['url']).status_code in (403, 404)


def test_invalid_dates_and_unknown_sources_remain_incomplete(app, world):
    with app.app_context():
        fields = draft_fields()
        fields.update(planned_start='tomorrow 8am', planned_end='2030-11-02T09:00',
                      group_name='Invented team', ci_sources=['S999'])
        draft = access.extract_extras('[[TICKET]] ' + json.dumps(fields), may_raise_change=True, tenant_id=1)['draft']
        bound = bind_draft(draft, scope_for(world.admin).identity, [])
        assert {'planned_start', 'planned_end', 'group_id', 'ci_ids'} <= set(bound['missing_fields'])
        assert bound['ci_ids'] == [] and bound['group_id'] is None
        fields.update(planned_start='2030-11-02T10:00+09:00', planned_end='2030-11-02T09:00+09:00')
        reversed_draft = access.extract_extras('[[TICKET]] ' + json.dumps(fields), may_raise_change=True, tenant_id=1)['draft']
        assert 'planned_start' not in reversed_draft and 'planned_end' not in reversed_draft


def test_draft_rechecks_ci_class_and_team_permissions(app, world):
    with app.app_context():
        ci = ConfigurationItem.query.filter_by(name='vpn-vault-hsm').one()
        fields = {**draft_fields(), 'ci_sources': ['S1'], 'group_name': 'Database'}
        draft = access.extract_extras('[[TICKET]] ' + json.dumps(fields), may_raise_change=True, tenant_id=1)['draft']
        sources = [{'id': 'S1', 'kind': 'ci', 'record_id': ci.id}]
        bound = bind_draft(draft, scope_for(world.outsider).identity, sources)
        assert bound['ci_ids'] == [] and bound['group_id'] is None
        assert bind_draft(draft, scope_for(world.admin).identity, sources)['ci_ids'] == [ci.id]


def test_prompt_uses_user_timezone_and_requires_change_fields(app, world):
    with app.app_context():
        prompt = access.chat_instructions(scope_for(world.admin))
        for value in ('Asia/Tokyo', 'planned_start', 'planned_end', 'implementation_plan', 'test_plan', 'backout_plan', 'ci_sources', 'group_name'):
            assert value in prompt


import os
import pytest


@pytest.mark.skipif(os.getenv('RUN_AI_DRAFT_BROWSER') != '1', reason='Enable complete change draft browser checks')
@pytest.mark.parametrize('width', [1440, 390])
def test_complete_change_draft_browser(app, client, world, width):
    import threading
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    from app import AIRun
    with app.app_context():
        team = SupportGroup.query.filter_by(name='Database').one()
        ci = ConfigurationItem(name='SAMPLE server', ci_class='Server', support_group_id=team.id, tenant_id=1)
        db.session.add(ci)
        db.session.flush()
        fields = {**draft_fields(), 'ci_sources': ['S1']}
        draft = access.extract_extras('[[TICKET]] ' + json.dumps(fields), may_raise_change=True, tenant_id=1)['draft']
        sources = [{'id': 'S1', 'kind': 'ci', 'record_id': ci.id}]
        draft = bind_draft(draft, scope_for(world.admin).identity, sources)
        run = AIRun(user_id=world.admin, tenant_id=1, actor_role='admin', config_revision=1,
                    request_key=str(uuid.uuid4()), kind='chat', status='completed', provider='self_hosted', model='test',
                    route_json=json.dumps({'draft': draft}), sources_json=json.dumps(sources))
        db.session.add(run)
        db.session.commit()
        run_id, ci_id, team_id = run.id, ci.id, team.id
    app.config.update(CSRF_ENABLED=True, SESSION_COOKIE_SECURE=False)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={'width': width, 'height': 1000})
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + '/login')
            page.locator('[name=username]').fill('admin')
            page.locator('[name=password]').fill('Admin123!')
            page.locator('button.primary').click()
            page.wait_for_load_state('networkidle')
            page.goto(base + f'/tickets/new/change?ai=1&draft_run={run_id}')
            page.wait_for_load_state('networkidle')
            expect(page.locator('[name=planned_start]')).to_have_value('2030-11-01T23:00')
            expect(page.locator('[name=planned_end]')).to_have_value('2030-11-02T00:00')
            expect(page.locator('[name=group_id]')).to_have_value(str(team_id))
            expect(page.locator('.lookup-chip')).to_contain_text('SAMPLE server')
            expect(page.locator('.lookup-chip [name=ci_id]')).to_have_value(str(ci_id))
            for name in ('implementation_plan', 'test_plan', 'backout_plan', 'description'):
                expect(page.locator(f'[name={name}]')).to_have_value(draft_fields()[name].strip())
            page.screenshot(path=f'/private/tmp/serviceops-ai-complete-draft-{width}.png', full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), page.evaluate("Array.from(document.querySelectorAll('body *')).filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,12).map(e=>({tag:e.tagName,cls:e.className,width:e.getBoundingClientRect().width}))")
            page.screenshot(path=f'/private/tmp/serviceops-ai-complete-draft-{width}.png', full_page=True)
            page.get_by_role('button', name='Create change', exact=True).click()
            page.wait_for_load_state('networkidle')
            assert '/ticket/' in page.url
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)
