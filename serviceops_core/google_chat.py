"""Pure Google Chat event/command parsing -- no Flask, DB, or network
dependency, matching serviceops_core.delivery's bounded-interface pattern.
Network I/O (Pub/Sub pull/ack, posting replies, OAuth2 token exchange) and
database access intentionally stay in app.py.
"""
import base64
import json
import re


COMMAND_PATTERN = re.compile(r"^/(\w+)(?:\s+(.*))?$", re.DOTALL)


def parse_command(text):
    """Returns (command, args) -- command lowercased, args stripped -- for a
    leading "/word ..." message, or None if the text isn't shaped like a
    command at all (an ordinary chat message, which is left alone)."""
    if not text:
        return None
    match = COMMAND_PATTERN.match(text.strip())
    if not match:
        return None
    return match.group(1).lower(), (match.group(2) or "").strip()


def decode_pubsub_message(received_message):
    """Decodes one Pub/Sub `pull` response's `receivedMessages[]` entry into
    (chat_event, ack_id). Pub/Sub base64-encodes the actual Chat event JSON
    inside `message.data`. Returns (None, ack_id) for a malformed/
    undecodable entry -- the caller still acknowledges it (an unparseable
    message must never retry forever and block every later one behind it,
    the same "one bad item never blocks the batch" stance already used by
    every process_*_schedule function in app.py)."""
    ack_id = received_message.get("ackId")
    try:
        raw = base64.b64decode(received_message["message"]["data"])
        return json.loads(raw), ack_id
    except (KeyError, TypeError, ValueError):
        return None, ack_id


def extract_message_event(chat_event):
    """Returns {"text", "thread_name", "sender_email"} for a MESSAGE-type
    Chat event with a real thread, or None for anything else (a space's
    ADDED_TO_SPACE/REMOVED_FROM_SPACE lifecycle event, a CARD_CLICKED
    interaction, or a malformed payload) -- those are acknowledged and
    otherwise ignored by the caller, since there is no command to act on
    without a thread to reply into."""
    if not isinstance(chat_event, dict) or chat_event.get("type") != "MESSAGE":
        return None
    message = chat_event.get("message")
    if not isinstance(message, dict):
        return None
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return None
    return {
        "text": message.get("text") or "",
        "thread_name": thread_name,
        "sender_email": ((message.get("sender") or {}).get("email") or "").strip().lower(),
    }
