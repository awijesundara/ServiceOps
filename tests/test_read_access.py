"""serviceops_core.read_access: the one read layer shared by the chat assistant,
incident investigations and the MCP server."""
import re
from pathlib import Path

from app import CiClassPermission, ConfigurationItem, Knowledge, Ticket, User, db, now
from serviceops_core import read_access
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)
from tests.test_mcp import api_client_for, call

ROOT = Path(__file__).resolve().parent.parent
DIRECT_QUERY = re.compile(r"visible_ticket_query|visible_knowledge_query|Knowledge\.query|ConfigurationItem\.query"
                          r"|restrict_ci_query_to_readable_classes|ci_class_read_allowed")


def test_ai_and_mcp_code_reads_tickets_knowledge_and_cis_only_through_read_access():
    offenders = []
    for path in [*sorted((ROOT / "serviceops_core" / "ai").glob("*.py")), ROOT / "serviceops_core" / "mcp_tools.py"]:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if DIRECT_QUERY.search(line) and not line.lstrip().startswith(("#", "(`", "2.", "3.")):
                offenders.append(f"{path.name}:{number}")
    assert not offenders, f"Use serviceops_core.read_access instead: {offenders}"


def add_ticket(number, **fields):
    requester = User.query.filter_by(username="admin").one()
    ticket = Ticket(number=number, kind="incident", title=number, description="d", category="Network", priority="P3",
                    state="New", requester_id=requester.id, tenant_id=1, **fields)
    db.session.add(ticket)
    db.session.commit()
    return ticket


def test_deleted_tickets_are_invisible_everywhere_including_mcp(app, client):
    with app.app_context():
        add_ticket("INC0081001")
        add_ticket("INC0081002", deleted_at=now())
        admin = User.query.filter_by(username="admin").one()
        numbers = {t.number for t in read_access.tickets(admin).filter(Ticket.number.like("INC00810%"))}
        assert numbers == {"INC0081001"}
    headers = api_client_for(app)
    found = call(client, headers, "search_tickets", {"query": "INC00810"})["structuredContent"]["tickets"]
    assert [row["number"] for row in found] == ["INC0081001"]
    assert call(client, headers, "get_ticket", {"number": "INC0081002"})["isError"]


def test_requesters_get_no_configuration_items_and_managed_classes_stay_hidden(app):
    with app.app_context():
        db.session.add_all([ConfigurationItem(name="ra-srv", ci_class="Server", tenant_id=1),
                            ConfigurationItem(name="ra-vault", ci_class="Secure Vault", tenant_id=1),
                            CiClassPermission(tenant_id=1, ci_class="Secure Vault", role="admin", can_read=True)])
        db.session.commit()
        employee = User.query.filter_by(username="employee").one()
        manager = User.query.filter_by(username="database.manager").one()
        admin = User.query.filter_by(username="admin").one()
        names = lambda user: {row.name for row in read_access.configuration_items(user).filter(  # noqa: E731
            ConfigurationItem.name.like("ra-%"))}
        assert names(employee) == set()
        assert names(manager) == {"ra-srv"}
        assert names(admin) == {"ra-srv", "ra-vault"}
        vault = ConfigurationItem.query.filter_by(name="ra-vault").one()
        assert not read_access.configuration_item_readable(manager, vault)
        assert read_access.configuration_item_readable(admin, vault)


def test_the_assistant_answers_only_from_current_published_knowledge(app):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        db.session.add_all([Knowledge(title="ra published", category="General", body="b", author_id=admin.id),
                            Knowledge(title="ra draft", category="General", body="b", author_id=admin.id,
                                      published=False),
                            Knowledge(title="ra archived", category="General", body="b", author_id=admin.id,
                                      archived=True)])
        db.session.commit()
        titles = lambda query: {row.title for row in query.filter(Knowledge.title.like("ra %"))}  # noqa: E731
        assert titles(read_access.published_knowledge(admin)) == {"ra published"}
        assert titles(read_access.reviewable_knowledge(admin)) == {"ra published", "ra draft", "ra archived"}
        employee = User.query.filter_by(username="employee").one()
        assert titles(read_access.reviewable_knowledge(employee)) == {"ra published", "ra archived"}
