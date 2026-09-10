import json

from serviceops_core.delivery import event_matches, google_chat_message, parse_event_patterns


def test_event_subscription_patterns_are_explicit_and_fail_closed():
    assert parse_event_patterns("") == ["*"]
    assert event_matches(json.dumps(["notification.created", "ticket.*"]), "notification.created")
    assert event_matches(json.dumps(["notification.created", "ticket.*"]), "ticket.updated")
    assert not event_matches(json.dumps(["notification.created"]), "audit.created")
    assert event_matches(
        json.dumps(["notification.created:approval.*"]),
        "notification.created", {"notification_event_type": "approval.requested"},
    )
    assert event_matches(
        json.dumps(["audit.created:ticket *"]),
        "audit.created", {"action": "ticket update"},
    )
    assert not event_matches("not-json", "notification.created")
    assert not event_matches(json.dumps({"bad": "shape"}), "notification.created")


def test_google_chat_payload_is_bounded_to_supported_text_shape():
    assert google_chat_message({"title": "Approval required", "body": "Review CHG001"}) == {
        "text": "*Approval required*\nReview CHG001"
    }
    assert google_chat_message({}) == {"text": "*ServiceOps event*"}
