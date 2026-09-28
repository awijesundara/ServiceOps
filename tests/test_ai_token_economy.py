"""Token economy: list questions get one line per ticket; a named ticket keeps its full detail."""
from tests.test_ai_privacy import payload, world  # noqa: F401
from tests.test_app import app  # noqa: F401


def test_list_questions_send_one_line_per_ticket(app, world):
    with app.app_context():
        listed, evidence = payload(world.employee, "what are my open tickets?")
        own = next(item for item in evidence.items if item.get("reference") == "INC0100001")
        assert "Summary only" in own["text"] and "Cannot reach VPN" not in own["text"]
        assert "State:" in own["text"] and "Priority:" in own["text"]


def test_asking_about_a_number_still_gets_the_full_record(app, world):
    with app.app_context():
        detailed, evidence = payload(world.employee, "tell me about INC0100001")
        own = next(item for item in evidence.items if item.get("reference") == "INC0100001")
        assert "Cannot reach VPN" in own["text"] and "Summary only" not in own["text"]

