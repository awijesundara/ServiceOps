"""serviceops_core.google_chat: parsing helpers for the Google Chat Pub/Sub
integration (see process_google_chat_pubsub_schedule() in app.py). Pure
logic, isolated from Flask/DB/network.
"""
import base64
import json

from serviceops_core.google_chat import decode_pubsub_message, extract_message_event, parse_command


def test_parse_command_extracts_command_and_args():
    assert parse_command("/ack") == ("ack", "")
    assert parse_command("/escalate Database") == ("escalate", "Database")
    assert parse_command("  /escalate   Database team  ") == ("escalate", "Database team")


def test_parse_command_is_case_insensitive_on_the_command_only():
    assert parse_command("/ACK") == ("ack", "")
    assert parse_command("/Escalate Database") == ("escalate", "Database")


def test_parse_command_returns_none_for_ordinary_messages():
    assert parse_command("just chatting, not a command") is None
    assert parse_command("") is None
    assert parse_command(None) is None
    # A bare slash with no word after it isn't a command either.
    assert parse_command("/") is None


def test_decode_pubsub_message_round_trips_a_real_chat_event():
    event = {"type": "MESSAGE", "message": {"text": "/ack"}}
    encoded = base64.b64encode(json.dumps(event).encode()).decode()
    decoded, ack_id = decode_pubsub_message({"ackId": "abc123", "message": {"data": encoded}})
    assert decoded == event
    assert ack_id == "abc123"


def test_decode_pubsub_message_fails_safe_on_malformed_data():
    decoded, ack_id = decode_pubsub_message({"ackId": "abc123", "message": {"data": "not-base64!!"}})
    assert decoded is None
    assert ack_id == "abc123"
    decoded, ack_id = decode_pubsub_message({"ackId": "xyz", "message": {}})
    assert decoded is None
    assert ack_id == "xyz"


def _mention_annotation(mention_text, bot=True, user_name="users/999"):
    return {
        "type": "USER_MENTION", "startIndex": 0, "length": len(mention_text),
        "userMention": {"user": {"name": user_name, "type": "BOT" if bot else "HUMAN"}},
    }


def test_extract_message_event_returns_text_thread_and_sender_with_the_mention_stripped():
    event = {
        "type": "MESSAGE",
        "message": {
            "text": "@ServiceOps /escalate Database",
            "thread": {"name": "spaces/AAAA/threads/BBBB"},
            "sender": {"email": "Agent@Example.com"},
            "annotations": [_mention_annotation("@ServiceOps")],
        },
    }
    result = extract_message_event(event, "users/999")
    assert result == {
        "text": "/escalate Database",
        "thread_name": "spaces/AAAA/threads/BBBB",
        "sender_email": "agent@example.com",
    }


def test_extract_message_event_ignores_non_message_event_types():
    assert extract_message_event({"type": "ADDED_TO_SPACE"}, "users/999") is None
    assert extract_message_event({"type": "CARD_CLICKED", "message": {"thread": {"name": "x"}}}, "users/999") is None


def test_extract_message_event_ignores_a_message_with_no_thread():
    event = {
        "type": "MESSAGE",
        "message": {
            "text": "@ServiceOps /ack", "sender": {"email": "a@b.com"},
            "annotations": [_mention_annotation("@ServiceOps")],
        },
    }
    assert extract_message_event(event, "users/999") is None


def test_extract_message_event_ignores_a_message_that_does_not_mention_this_app():
    """The defense-in-depth half of the /ack-vs-another-Chat-app collision
    fix: a plain "/ack" with no bot @mention at all (e.g. Google delivered
    it for some other reason, or a differently-addressed message) must be
    ignored, not treated as a command aimed at ServiceOps."""
    event = {
        "type": "MESSAGE",
        "message": {
            "text": "/ack", "thread": {"name": "spaces/AAAA/threads/BBBB"},
            "sender": {"email": "a@b.com"},
        },
    }
    assert extract_message_event(event, "users/999") is None
    # A mention of a *human*, not this bot, must not count either.
    event["message"]["annotations"] = [_mention_annotation("@Someone", bot=False)]
    assert extract_message_event(event, "users/999") is None


def test_extract_message_event_rejects_a_different_bot_mention():
    event = {
        "type": "MESSAGE",
        "message": {
            "text": "@OtherBot /ack", "thread": {"name": "spaces/AAAA/threads/BBBB"},
            "sender": {"email": "a@b.com"},
            "annotations": [_mention_annotation("@OtherBot", user_name="users/other-bot")],
        },
    }
    assert extract_message_event(event, "users/serviceops-bot") is None
    assert extract_message_event(event, "") is None


def test_extract_message_event_handles_malformed_payloads_without_raising():
    assert extract_message_event(None, "users/999") is None
    assert extract_message_event({}, "users/999") is None
    assert extract_message_event({"type": "MESSAGE"}, "users/999") is None
    assert extract_message_event({"type": "MESSAGE", "message": "not-a-dict"}, "users/999") is None
