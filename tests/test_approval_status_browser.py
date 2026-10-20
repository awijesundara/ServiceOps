"""Approval statuses read at a glance in a real browser: Requested and Approved
have their own colours, decisions that no longer count are greyed out and listed
after the current ones, and every theme passes axe."""
import os
import re
import threading

import pytest
from werkzeug.serving import make_server

from app import THEMES, ApprovalChain, ConfigurationItem, Ticket, User, UserPreference, db, decide_vote
from tests.test_app import app, client, group_id, login  # noqa: F401
from tests.test_ci_owner_approval import _person

pytestmark = pytest.mark.skipif(os.getenv("RUN_INCIDENT_BROWSER") != "1",
                                reason="RUN_INCIDENT_BROWSER=1 enables real local browser checks")


def _change_with_history(client, app):
    with app.app_context():
        alice, carol = _person("alice.status"), _person("carol.status")
        first = ConfigurationItem(name="status-app", ci_class="Server", owner_id=alice.id)
        later = ConfigurationItem(name="status-lb", ci_class="Server", owner_id=carol.id)
        db.session.add_all([first, later])
        db.session.commit()
        first_id, later_id = first.id, later.id
    login(client)
    client.post("/tickets/new/change", data={
        "title": "Status colours", "description": "x", "category": "Software", "priority": "P3",
        "change_type": "Standard", "risk_score": "20", "impact": "Low", "group_id": group_id(app, "Unix"),
        "implementation_plan": "i", "test_plan": "t", "backout_plan": "b",
        "planned_start": "2026-12-01T09:00", "planned_end": "2026-12-01T10:00", "ci_id": str(first_id)})
    with app.app_context():
        ticket_id = Ticket.query.filter_by(title="Status colours").one().id
    # A CI added later supersedes the first round: its votes no longer count.
    client.post(f"/record/ticket/{ticket_id}/configuration-items",
                data={"relationship_role": "Affected CI", "ci_id": str(later_id)})
    with app.app_context():
        chain = ApprovalChain.query.filter_by(target_type="ticket", target_id=ticket_id, state="Running").one()
        vote = next(v for gate in chain.gates for v in gate.votes if v.state == "Requested")
        with app.test_request_context():
            from flask_login import login_user
            login_user(db.session.get(User, vote.approver_id))
            decide_vote(vote, "Approved", "Looks good.")
        db.session.commit()
    return ticket_id


def test_approval_statuses_in_every_theme(client, app):
    from playwright.sync_api import expect, sync_playwright
    ticket_id = _change_with_history(client, app)
    app.config.update(SESSION_COOKIE_SECURE=False)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce").new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(base + "/login")
            page.locator('input[name="username"]').fill("admin")
            page.locator('input[name="password"]').fill("Admin123!")
            page.locator("button.primary").click()
            page.wait_for_load_state("networkidle")
            for theme in THEMES:
                with app.app_context():
                    admin = User.query.filter_by(username="admin").one()
                    preference = UserPreference.query.filter_by(user_id=admin.id).first() \
                        or UserPreference(user_id=admin.id)
                    preference.theme = theme
                    db.session.add(preference)
                    db.session.commit()
                page.goto(base + f"/ticket/{ticket_id}?theme={theme}#gov-approvers")  # a real load per theme
                expect(page.locator("body")).to_have_class(re.compile(f"theme-{theme}"))
                rows = page.locator("#gov-approvers tbody tr")
                states = [rows.nth(i).locator(".status-badge").inner_text() for i in range(rows.count())]
                # Current decisions first, then the superseded round, greyed out.
                assert states.index("No Longer Required") > max(states.index("Approved"), states.index("Requested"))
                expect(page.locator("#gov-approvers tr.status-row-inactive").first).to_contain_text("No Longer Required")
                colours = {name: page.locator(f"#gov-approvers .status-badge.{name}").first.evaluate(
                    "el => getComputedStyle(el).backgroundColor") for name in ("approved", "requested", "no-longer-required")}
                assert len(set(colours.values())) == 3, (theme, colours)
                axe = os.getenv("AXE_CORE_PATH")
                assert axe and os.path.isfile(axe), "AXE_CORE_PATH required for accessibility acceptance"
                page.evaluate(open(axe, encoding="utf-8").read())
                violations = page.evaluate("async () => (await axe.run(document.querySelector('#gov-approvers'), "
                                           "{runOnly: {type:'tag', values:['wcag2a','wcag2aa']}})).violations")
                assert not violations, (theme, [(v["id"], [(n["target"], n.get("any", [{}])[0].get("message", "")[:160]) for n in v["nodes"][:4]]) for v in violations])
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
