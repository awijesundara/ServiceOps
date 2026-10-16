"""Per-request permission caches: one query per request for role policy,
team membership and the Executive Office, never stale after a write in the
same request, and query budgets for the notification poll."""
import pytest

from werkzeug.security import generate_password_hash

from app import (
    GroupMember, Notification, RolePolicyOverride, SupportGroup, Ticket, TicketAssignmentGroup, User, db,
    effective_role_has_action, executive_office_group, membership_group_ids, user_can_manage_ticket,
    user_support_group_ids,
)
from tests.test_app import app, client, login  # noqa: F401 - pytest fixtures
from tests.test_request_performance import count_queries


def test_role_policy_overrides_load_once_and_see_writes(app):
    with app.test_request_context("/"):
        tenant_id = User.query.filter_by(username="admin").one().tenant_id
        first = count_queries(app, lambda: [effective_role_has_action("agent", action, tenant_id)
                                            for action in ("comment_internal", "update", "assign", "transition")])
        assert sum("FROM role_policy_override" in sql for sql in first) == 1
        assert count_queries(app, lambda: effective_role_has_action("agent", "update", tenant_id)) == []
        baseline = effective_role_has_action("agent", "comment_internal", tenant_id)
        db.session.add(RolePolicyOverride(tenant_id=tenant_id, role="agent", action="comment_internal",
                                          is_granted=not baseline))
        db.session.flush()  # a write in the same request drops the cache
        assert effective_role_has_action("agent", "comment_internal", tenant_id) is (not baseline)
        db.session.rollback()


def test_team_membership_loads_once_and_sees_writes(app):
    with app.test_request_context("/"):
        user = User.query.filter_by(username="employee").one()
        windows = SupportGroup.query.filter_by(name="Windows").one()
        before = user_support_group_ids(user)
        assert count_queries(app, lambda: user_support_group_ids(user)) == []
        assert count_queries(app, lambda: membership_group_ids(user)) != []
        assert count_queries(app, lambda: membership_group_ids(user)) == []
        db.session.add(GroupMember(group_id=windows.id, user_id=user.id, role="member"))
        db.session.flush()
        assert windows.id in user_support_group_ids(user) and windows.id not in before
        assert windows.id in membership_group_ids(user)
        windows.active = False
        db.session.flush()
        assert windows.id not in user_support_group_ids(user)  # inactive teams still excluded
        assert windows.id in membership_group_ids(user)  # raw memberships keep it, as before
        db.session.rollback()


def test_executive_office_lookup_is_cached_and_refreshed_on_write(app):
    with app.test_request_context("/"):
        admin = User.query.filter_by(username="admin").one()
        first = executive_office_group(admin.tenant_id)
        assert count_queries(app, lambda: executive_office_group(admin.tenant_id)) == []
        if first is None:
            db.session.add(SupportGroup(name="Executive Office", group_type="Executive", tenant_id=admin.tenant_id))
            db.session.flush()
            assert executive_office_group(admin.tenant_id) is not None
        db.session.rollback()


def test_manage_permission_unchanged_for_members_managers_and_outsiders(app):
    with app.test_request_context("/"):
        admin = User.query.filter_by(username="admin").one()
        core_apps = SupportGroup.query.filter_by(name="CoreApps").one()
        ticket = Ticket(number="PRM0000001", kind="incident", title="x", description="x", category="Software",
                        priority="P3", state="New", requester_id=admin.id, tenant_id=admin.tenant_id)
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=core_apps.id))
        member = User(username="perm.member", name="Perm Member", email="perm.member@test.invalid",
                      password_hash=generate_password_hash("x" * 20), role="agent")
        outsider = User(username="perm.outsider", name="Perm Outsider", email="perm.outsider@test.invalid",
                        password_hash=generate_password_hash("x" * 20), role="agent")
        db.session.add_all([member, outsider])
        db.session.flush()
        db.session.add(GroupMember(group_id=core_apps.id, user_id=member.id, role="member"))
        db.session.flush()
        assert user_can_manage_ticket(member, ticket) is True
        assert user_can_manage_ticket(outsider, ticket) is False
        # Membership removed mid-request: the cached set is dropped with it.
        GroupMember.query.filter_by(group_id=core_apps.id, user_id=member.id).delete()
        db.session.flush()
        assert user_can_manage_ticket(member, ticket) is False
        db.session.rollback()


def test_notification_poll_query_budget_and_shape(client, app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        tickets = Ticket.query.filter_by(tenant_id=admin.tenant_id).limit(3).all()
        for n in range(6):
            target = tickets[n % len(tickets)] if tickets else None
            db.session.add(Notification(user_id=admin.id, tenant_id=admin.tenant_id, title=f"N{n}", body="b",
                                        severity="critical" if n == 2 else "info", read=n == 5,
                                        target_type="ticket" if target else None,
                                        target_id=target.id if target else None))
        db.session.commit()
    login(client)
    client.get("/notifications/poll")
    statements = count_queries(app, lambda: client.get("/notifications/poll"))
    notification_queries = [sql for sql in statements if "FROM notification" in sql]
    ticket_queries = [sql for sql in statements if "FROM ticket" in sql]
    assert len(notification_queries) <= 2, notification_queries
    assert len(ticket_queries) <= 1, "targets must load in one query per type"
    data = client.get("/notifications/poll").get_json()
    assert data["unread_count"] == 5 and data["severity"] == "critical"
    assert len(data["notifications"]) == 6 and data["latest_id"] == data["notifications"][0]["id"]
    assert all("has_target" in row for row in data["notifications"])


@pytest.mark.parametrize("nested", [False, True])
def test_permission_cache_is_invalidated_by_rollback(app, nested):
    with app.test_request_context("/"):
        user = User.query.filter_by(username="employee").one()
        group = SupportGroup.query.filter_by(name="Windows").one()
        tenant_id = user.tenant_id
        before = user_support_group_ids(user)
        baseline = effective_role_has_action("agent", "security_administer", tenant_id)
        transaction = db.session.begin_nested() if nested else db.session()
        db.session.add(RolePolicyOverride(tenant_id=tenant_id, role="agent", action="security_administer",
                                          is_granted=not baseline))
        db.session.add(GroupMember(group_id=group.id, user_id=user.id))
        db.session.flush()
        assert effective_role_has_action("agent", "security_administer", tenant_id) is not baseline
        assert group.id in user_support_group_ids(user)
        assert group.id in membership_group_ids(user)
        transaction.rollback()
        assert effective_role_has_action("agent", "security_administer", tenant_id) is baseline
        assert user_support_group_ids(user) == before
        assert group.id not in membership_group_ids(user)
