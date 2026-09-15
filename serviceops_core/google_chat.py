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


def _strip_bot_mention(message):
    """Returns the message text with a leading bot @mention annotation
    removed, or None if the message doesn't mention a bot at all.

    Google Chat only delivers a *space's* (as opposed to a 1:1 direct
    message's) MESSAGE event to an app when that app is explicitly
    @-mentioned, unless the app opts into receiving every message in every
    space it's a member of -- ServiceOps's Chat app configuration
    deliberately does not request that broader permission (see
    DEPLOYMENT.md's Google Chat bot section). That single choice is what
    keeps ServiceOps from ever seeing (and this function's defense-in-depth
    re-check from ever acting on) a plain "/ack" meant for a different Chat
    app sharing the same space -- each app is only ever handed the
    messages that explicitly named it, addressed as e.g. "@ServiceOps
    /ack", which is also why the mention has to be stripped before the
    remaining text can match COMMAND_PATTERN's leading "/word" shape."""
    text = message.get("text") or ""
    for annotation in message.get("annotations") or []:
        if annotation.get("type") != "USER_MENTION":
            continue
        mention_user = (annotation.get("userMention") or {}).get("user") or {}
        if mention_user.get("type") != "BOT":
            continue
        start = annotation.get("startIndex", 0)
        length = annotation.get("length", 0)
        return (text[:start] + text[start + length:]).strip()
    return None


def extract_message_event(chat_event):
    """Returns {"text", "thread_name", "sender_email"} for a MESSAGE-type
    Chat event that explicitly @-mentions this app and has a real thread,
    or None for anything else -- a space lifecycle event
    (ADDED_TO_SPACE/REMOVED_FROM_SPACE), a CARD_CLICKED interaction, a
    malformed payload, a message with no thread to reply into, or (see
    _strip_bot_mention's docstring) a message not actually addressed to
    this app. All of those are acknowledged and otherwise ignored by the
    caller."""
    if not isinstance(chat_event, dict) or chat_event.get("type") != "MESSAGE":
        return None
    message = chat_event.get("message")
    if not isinstance(message, dict):
        return None
    thread_name = ((message.get("thread") or {}).get("name") or "").strip()
    if not thread_name:
        return None
    stripped_text = _strip_bot_mention(message)
    if stripped_text is None:
        return None
    return {
        "text": stripped_text,
        "thread_name": thread_name,
        "sender_email": ((message.get("sender") or {}).get("email") or "").strip().lower(),
    }
