"""What the assistant remembers about a person, on their explicit say-so.

Deliberately small and safe: notes are created only when the person asks ("remember that ...") or clicks
"Remember" on a suggestion, are private to that person and tenant, are shown to them and deletable at any
time, never hold passwords, keys or payment numbers, and are purged when the person is erased. A note that
contains personal details keeps the conversation on the organization's own AI like any other sensitive text.
Retrieval is by shared words, not embeddings: at this size that is simple, explainable and needs no extra service.
"""
import re
from types import SimpleNamespace

from serviceops_core.ai import routing
from serviceops_models import AIMemory, db, now

MAX_NOTES = 30
MAX_CHARS = 240
_REMEMBER = re.compile(r"^\s*(?:please\s+)?(?:remember|keep in mind)(?:\s+that|\s+this)?\s*[:,-]?\s+(.{3,})$", re.I | re.S)
_STANDING = re.compile(r"^\s*(?:from now on|going forward|in future|in the future)\s*[:,-]?\s+(.{3,})$", re.I | re.S)
_FORGET_ALL = re.compile(r"^\s*(?:please\s+)?forget\s+(?:everything|all(?:\s+of)?\s+(?:it|that|this)?(?:\s+about me)?|what you know about me)\s*[.!]?\s*$", re.I)
_PREFERENCE = re.compile(r"\b(prefer|always|never|from now on|reply|respond|answer|explain|short|brief|detailed|simple|plain|language|tone|format)\b", re.I)
_STOP = frozenset("the a an and or of to in on for with about is are was were be this that it my me i you your do does did how what when where why can could should".split())


def parse_command(question):
    """('remember', text) / ('forget_all', '') / None: what a message asks of the memory, if anything."""
    if _FORGET_ALL.match(question or ""):
        return "forget_all", ""
    for pattern in (_REMEMBER, _STANDING):
        match = pattern.match(question or "")
        if match:
            text = " ".join(match.group(1).split()).strip(" .")
            return "remember", (f"From now on, {text}" if pattern is _STANDING else text)
    return None


def _config_for_scan(config):
    return SimpleNamespace(detect_personal=True, detect_credentials=True, detect_financial=True,
                           sensitive_terms=getattr(config, "sensitive_terms", "") if config else "")


def notes_for(scope):
    return AIMemory.query.filter_by(tenant_id=scope.tenant_id, user_id=scope.user_id).order_by(AIMemory.created_at.desc()).all()


def store(scope, text, config=None, source="asked"):
    """Save one note. Returns (note, message); note is None when it was refused, with a plain-language reason."""
    text = " ".join((text or "").split())
    if len(text) < 3:
        return None, "Tell me what to remember."
    if len(text) > MAX_CHARS:
        return None, f"That is a bit long. Please keep it under {MAX_CHARS} characters."
    found = routing.scan(text, _config_for_scan(config))
    if found & {"credentials", "financial"}:
        return None, "I won't remember passwords, keys or payment and bank numbers. Please keep those out of our chats."
    existing = notes_for(scope)
    if any(n.text.lower() == text.lower() for n in existing):
        return next(n for n in existing if n.text.lower() == text.lower()), "I already have that noted."
    if len(existing) >= MAX_NOTES:
        return None, f"I can keep {MAX_NOTES} notes. Remove one from Memory first."
    note = AIMemory(tenant_id=scope.tenant_id, user_id=scope.user_id, text=text, source=source,
                    kind="preference" if _PREFERENCE.search(text) else "fact")
    db.session.add(note)
    db.session.flush()
    return note, "Got it. I'll remember that."


def clear(scope):
    total = AIMemory.query.filter_by(tenant_id=scope.tenant_id, user_id=scope.user_id).delete(synchronize_session=False)
    return total


def _words(text):
    return {w for w in re.findall(r"[a-z0-9]{3,}", (text or "").lower()) if w not in _STOP}


def relevant(scope, question, limit=5):
    """Notes worth showing the model for this question: standing preferences, plus notes that share words with it."""
    asked = _words(question)
    chosen, facts = [], []
    for note in notes_for(scope):
        if note.kind == "preference":
            chosen.append(note)
        elif asked & _words(note.text):
            facts.append(note)
    return (chosen[:3] + facts)[:limit]


def add_to_evidence(scope, question, evidence, config):
    """Give the model this person's relevant notes as context. Returns how many were used."""
    used = relevant(scope, question)
    if not used:
        return 0
    evidence.add_context("info", "Notes this person asked you to remember (their own words)",
                         " | ".join(n.text for n in used))
    for note in used:
        if evidence.scanner:
            evidence.scanner(note.text, "memory")  # a note with personal details keeps the chat on private AI
        note.last_used_at, note.use_count = now(), (note.use_count or 0) + 1
    return len(used)
