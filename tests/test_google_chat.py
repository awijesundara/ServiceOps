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


def test_extract_message_event_returns_text_thread_and_sender():
    event = {
        "type": "MESSAGE",
        "message": {
            "text": "/escalate Database",
            "thread": {"name": "spaces/AAAA/threads/BBBB"},
            "sender": {"email": "Agent@Example.com"},
        },
    }
    result = extract_message_event(event)
    assert result == {
        "text": "/escalate Database",
        "thread_name": "spaces/AAAA/threads/BBBB",
        "sender_email": "agent@example.com",
    }


def test_extract_message_event_ignores_non_message_event_types():
    assert extract_message_event({"type": "ADDED_TO_SPACE"}) is None
    assert extract_message_event({"type": "CARD_CLICKED", "message": {"thread": {"name": "x"}}}) is None


def test_extract_message_event_ignores_a_message_with_no_thread():
    event = {"type": "MESSAGE", "message": {"text": "/ack", "sender": {"email": "a@b.com"}}}
    assert extract_message_event(event) is None


def test_extract_message_event_handles_malformed_payloads_without_raising():
    assert extract_message_event(None) is None
    assert extract_message_event({}) is None
    assert extract_message_event({"type": "MESSAGE"}) is None
    assert extract_message_event({"type": "MESSAGE", "message": "not-a-dict"}) is None
