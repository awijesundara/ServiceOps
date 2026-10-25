"""Approval queue control geometry, responsive reflow and real decisions."""
import os
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from werkzeug.serving import make_server
from app import (ApprovalChain, ApprovalGate, ApprovalVote, ApprovalDelegation, ChangeGovernance,
                 ChangeOwnership, ConfigurationItem, SupportGroup, Ticket, User, UserPreference, db, now)
from tests.test_app import app  # noqa: F401

pytestmark = pytest.mark.skipif(os.getenv('RUN_APPROVAL_LAYOUT_BROWSER') != '1', reason='opt-in real browser')


@pytest.mark.parametrize('width,theme', [(1728,'light'),(1280,'dark'),(768,'light'),(390,'dark')])
def test_approval_queue_geometry_and_decision(app, width, theme):
    from playwright.sync_api import sync_playwright, expect
    with app.app_context():
        admin=User.query.filter_by(username='admin').one()
        manager=User.query.filter_by(username='database.manager').one()
        employee=User.query.filter_by(username='employee').one()
        group=SupportGroup.query.filter_by(name='Unix').one()
        preference=UserPreference.query.filter_by(user_id=admin.id).first() or UserPreference(user_id=admin.id)
        preference.theme=theme; db.session.add(preference)
        ci=ConfigurationItem(name='production-api.example.invalid',ci_class='Server',tenant_id=1)
        db.session.add(ci); db.session.flush()
        votes=[]
        for index in range(3):
            ticket=Ticket(number=f'CHG990000{index}',kind='change',title='Production application maintenance and infrastructure change '+str(index),
                          description='Review implementation and backout plans.',category='Software',state='Awaiting Approval',
                          priority='P3',requester_id=employee.id,tenant_id=1)
            db.session.add(ticket);db.session.flush()
            db.session.add(ChangeOwnership(ticket_id=ticket.id,group_id=group.id))
            db.session.add(ChangeGovernance(ticket_id=ticket.id,ci_id=ci.id,tenant_id=1,change_type='Normal',risk_score=55,
                                           implementation_plan='Deploy',test_plan='Verify',backout_plan='Restore',
                                           planned_start=now()+timedelta(days=2),planned_end=now()+timedelta(days=3)))
            chain=ApprovalChain(name=f'{ticket.number} change authorization with complete decision history',target_type='ticket',target_id=ticket.id,tenant_id=1)
            db.session.add(chain);db.session.flush()
            gate=ApprovalGate(chain_id=chain.id,sequence=1,name='Unix manager assessment',mode='all',state='Requested',tenant_id=1)
            db.session.add(gate);db.session.flush()
            vote=ApprovalVote(gate_id=gate.id,approver_id=manager.id if index==2 else admin.id,state='Requested',tenant_id=1)
            db.session.add(vote);db.session.flush();votes.append(vote.id)
        db.session.add(ApprovalDelegation(from_user_id=manager.id,to_user_id=admin.id,tenant_id=1,starts_at=now()-timedelta(days=1),
                                         ends_at=now()+timedelta(days=1),reason='Leave',created_by_id=manager.id))
        db.session.commit()
    app.config.update(CSRF_ENABLED=True,SESSION_COOKIE_SECURE=False)
    server=make_server('127.0.0.1',0,app,threaded=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch()
            page=browser.new_page(viewport={'width':width,'height':1000},reduced_motion='reduce')
            errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
            base=f'http://127.0.0.1:{server.server_port}'
            page.goto(base+'/login');page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill('Admin123!')
            page.locator('button.primary').click();page.wait_for_load_state('networkidle')
            page.goto(base+'/approval-chains');page.wait_for_load_state('networkidle')
            expect(page.locator('.pending-box article')).to_have_count(3)
            page.screenshot(path=f'/private/tmp/approval-layout-{os.getenv("APPROVAL_LAYOUT_PHASE","after")}-{width}.png',full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth+1')
            panel=page.locator('.pending-box').first.bounding_box();table=page.locator('.list-workspace').bounding_box()
            assert abs(panel['x']-table['x'])<=1 and abs(panel['width']-table['width'])<=1
            for form in page.locator('.pending-box article form').all():
                buttons=form.locator('button').all();field=form.locator('[name=comments]').bounding_box()
                boxes=[button.bounding_box() for button in buttons]
                assert all(36<=box['height']<=48 for box in boxes),boxes
                assert abs(boxes[0]['height']-boxes[1]['height'])<=1
                if width>=1100:
                    assert all(abs(box['y']-field['y'])<=1 for box in boxes),(field,boxes)
            names=page.locator('.task-list>tbody>tr>td:first-child strong')
            for name in names.all():
                assert name.evaluate('el=>getComputedStyle(el).whiteSpace')!='nowrap'
            axe=Path(os.environ['AXE_CORE_PATH']).read_text();page.evaluate(axe)
            violations=page.evaluate("async()=> (await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa']}})).violations")
            assert not violations,[(v['id'],[n['target'] for n in v['nodes']]) for v in violations]
            decision=page.locator(f'form[action="/approval-votes/{votes[0]}/decide"]')
            decision.locator('[name=comments]').fill('Needs a revised implementation window.')
            decision.get_by_role('button',name='Reject',exact=True).click();page.wait_for_load_state('networkidle')
            with app.app_context():
                vote=db.session.get(ApprovalVote,votes[0]);assert vote.state=='Rejected'
                assert vote.comments=='Needs a revised implementation window.'
            assert not errors,errors
            browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)
