import json

from serviceops_core.delivery import (
    event_matches, google_chat_message, parse_event_patterns,
    provider_endpoint_allowed, provider_payload,
)


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


def test_provider_payloads_follow_each_chat_api_shape():
    event = {"title": "Approval required", "body": "Review CHG001"}
    assert provider_payload("slack", event) == {
        "text": "Approval required\nReview CHG001"
    }
    assert provider_payload("discord", event) == {
        "content": "Approval required\nReview CHG001"
    }
    assert provider_payload("telegram", event, {
        "chat_id": "-1001", "message_thread_id": 42, "protect_content": True,
    }) == {
        "chat_id": "-1001", "text": "Approval required\nReview CHG001",
        "message_thread_id": 42, "protect_content": True,
    }


def test_provider_endpoint_hosts_fail_closed_for_copied_secrets():
    assert provider_endpoint_allowed("google_chat", "chat.googleapis.com")
    assert not provider_endpoint_allowed("google_chat", "attacker.example")
    assert provider_endpoint_allowed("slack", "hooks.slack.com")
    assert provider_endpoint_allowed("webhook", "hooks.internal.example")
