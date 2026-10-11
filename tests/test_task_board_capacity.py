"""The task board decides card permissions in a fixed number of queries,
with exactly the same answers as user_can_manage_ticket()."""
from sqlalchemy import event
from werkzeug.security import generate_password_hash

from app import (
    ChangeOwnership, GroupMember, SupportGroup, Tenant, Ticket, TicketAssignmentGroup, User, db,
    manageable_ticket_ids, user_can_manage_ticket,
)
from tests.test_app import app, client, login  # noqa: F401 - pytest fixtures


def make_tickets(app):
    """Incidents and changes owned by several teams, one unassigned and one
    in another tenant."""
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        groups = {name: SupportGroup.query.filter_by(name=name).one() for name in ("CoreApps", "Network", "Windows")}
        ids = []
        for n, (kind, team) in enumerate([("incident", "CoreApps"), ("incident", "Network"), ("change", "Windows"),
                                          ("change", "CoreApps"), ("incident", None)]):
            ticket = Ticket(number=f"BRD{n:07d}", kind=kind, title=f"Board {n}", description="x", category="Software",
                            priority="P3", state="New", requester_id=admin.id, tenant_id=admin.tenant_id)
            db.session.add(ticket)
            db.session.flush()
            if team and kind == "change":
                db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=groups[team].id))
                # A stale assignment row must not override the change's ownership.
                db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=groups["Network"].id))
            elif team:
                db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=groups[team].id))
            ids.append(ticket.id)
        other = Tenant(slug="board-other", name="Other")
        db.session.add(other)
        db.session.flush()
        foreign = Ticket(number="BRD9999999", kind="incident", title="Foreign", description="x", category="Software",
                         priority="P3", state="New", requester_id=admin.id, tenant_id=other.id)
        db.session.add(foreign)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=foreign.id, group_id=groups["CoreApps"].id))
        ids.append(foreign.id)
        # A CoreApps member, a Windows manager, and someone in no team.
        member = User(username="board.member", name="Board Member", email="board.member@test.invalid",
                      password_hash=generate_password_hash("x" * 20), role="agent")
        boss = User(username="board.boss", name="Board Boss", email="board.boss@test.invalid",
                    password_hash=generate_password_hash("x" * 20), role="manager")
        loner = User(username="board.loner", name="Board Loner", email="board.loner@test.invalid",
                     password_hash=generate_password_hash("x" * 20), role="agent")
        db.session.add_all([member, boss, loner])
        db.session.flush()
        db.session.add(GroupMember(group_id=groups["CoreApps"].id, user_id=member.id, role="member"))
        groups["Windows"].manager_id = boss.id
        db.session.commit()
        return ids


def test_batched_permissions_match_the_per_ticket_rule(app):
    ids = make_tickets(app)
    with app.app_context():
        tickets = Ticket.query.filter(Ticket.id.in_(ids)).all()
        for username in ("admin", "board.member", "board.boss", "board.loner", "employee"):
            user = User.query.filter_by(username=username).one()
            expected = {ticket.id for ticket in tickets if user_can_manage_ticket(user, ticket)}
            assert manageable_ticket_ids(user, tickets) == expected, username
        member = User.query.filter_by(username="board.member").one()
        assert manageable_ticket_ids(member, tickets)  # sanity: the comparison is not vacuous
        member.active = False
        assert manageable_ticket_ids(member, tickets) == set()


def test_board_permission_check_uses_a_fixed_number_of_queries(app):
    ids = make_tickets(app)
    with app.app_context():
        tickets = Ticket.query.filter(Ticket.id.in_(ids)).all()
        user = User.query.filter_by(username="board.member").one()
        user.id  # load before counting
        statements = []
        listener = lambda *args: statements.append(args[2])  # noqa: E731
        event.listen(db.engine, "before_cursor_execute", listener)
        try:
            manageable_ticket_ids(user, tickets)
        finally:
            event.remove(db.engine, "before_cursor_execute", listener)
        assert len(statements) <= 4


def test_board_page_marks_only_manageable_cards_draggable(client, app):
    make_tickets(app)
    with app.app_context():
        user = User.query.filter_by(username="board.member").one()
        user.password_hash = generate_password_hash("Passw0rd!x")
        db.session.commit()
    login(client, "board.member", "Passw0rd!x")
    page = client.get("/task-board").get_data(as_text=True)
    with app.app_context():
        own = Ticket.query.filter_by(number="BRD0000000").one().id
        other = Ticket.query.filter_by(number="BRD0000001").one().id
    assert f'draggable="true" data-ticket="{own}"' in page
    assert f'draggable="false" data-ticket="{other}"' in page
