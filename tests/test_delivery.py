import json

from serviceops_core.delivery import (
    connection_accepts_event, event_matches, google_chat_message, parse_event_patterns,
    provider_endpoint_allowed, provider_payload,
)
from types import SimpleNamespace


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


def test_delivery_audiences_fail_closed_across_users_and_groups():
    personal = SimpleNamespace(
        scope_type="user", owner_user_id=7, support_group_id=None,
        event_types_json=json.dumps(["notification.created:approval.requested"]),
    )
    payload = {"user_id": 7, "notification_event_type": "approval.requested"}
    assert connection_accepts_event(personal, "notification.created", payload)
    assert not connection_accepts_event(personal, "notification.created", {**payload, "user_id": 8})
    assert not connection_accepts_event(personal, "activity.created", {"support_group_ids": [7]})

    team = SimpleNamespace(
        scope_type="group", owner_user_id=None, support_group_id=12,
        event_types_json=json.dumps(["activity.created:incidents"]),
    )
    assert connection_accepts_event(team, "activity.created", {
        "activity_category": "incidents", "support_group_ids": [12],
    })
    assert not connection_accepts_event(team, "activity.created", {
        "activity_category": "incidents", "support_group_ids": [13],
    })
    assert not connection_accepts_event(team, "notification.created", payload)

    organization = SimpleNamespace(
        scope_type="tenant", owner_user_id=None, support_group_id=None,
        event_types_json=json.dumps(["notification.created", "activity.created:incidents"]),
    )
    assert not connection_accepts_event(organization, "notification.created", payload)
    assert connection_accepts_event(organization, "activity.created", {
        "activity_category": "incidents",
    })
