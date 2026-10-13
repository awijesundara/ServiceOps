"""Task board lanes always carry an (empty-state) drop zone and a live count;
approval chains link to the record they approve."""
import re

from app import ApprovalChain, User, create_ticket_with_unique_number, db
from tests.test_app import app, client, login  # noqa: F401


def test_every_board_lane_has_a_drop_zone_and_count(app, client):
    login(client)
    page = client.get("/task-board").get_data(as_text=True)
    lanes = page.count('class="board-lane"')
    assert lanes and page.count('class="board-empty"') == lanes
    assert page.count('class="board-count" data-count=') == lanes
    # Lanes with cards keep the placeholder hidden; empty lanes show it.
    for lane in re.findall(r'<div class="board-lane".*?</div>\s*(?:<a class="board-hidden"[^>]*>[^<]*</a>\s*)?</div>', page, re.S):
        has_cards = 'class="board-card sla-' in lane
        assert ('<p class="board-empty" hidden>' in lane) == has_cards


def test_approval_chains_link_to_the_record_they_approve(app, client):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        change = create_ticket_with_unique_number("change", title="Upgrade firewall", description="x",
                                                  priority="P3", requester_id=admin.id)
        db.session.flush()
        db.session.add(ApprovalChain(name="Upgrade firewall approval", target_type="ticket", target_id=change.id,
                                     tenant_id=admin.tenant_id, state="Requested", current_stage=1))
        db.session.commit()
        number, change_id = change.number, change.id
    login(client)
    page = client.get("/approval-chains").get_data(as_text=True)
    assert f'<a class="approval-target" href="/ticket/{change_id}"><span>{number}</span>' in page
    assert client.get(f"/approval-chains?q={number}").get_data(as_text=True).count("approval-target") == 1
