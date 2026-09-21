"""Which AI service answers a request, and what may leave the organization.

Two questions are answered here, in this order, and never the other way round:

1. Privacy. Is anything in the request sensitive (personal details, passwords or keys,
   payment numbers, words the administrator listed)? If so, only services on the
   organization's own network are eligible. This is a hard rule: a failing or busy
   private service is never replaced by an external one.
2. Load and health. Among the eligible services, pick by the configured mode, keeping
   busy or recently failing services at the back of the queue.
"""
import random
import re
from dataclasses import dataclass, field
from datetime import timedelta

from serviceops_core.security import EMAIL_PATTERN, PHONE_PATTERNS
from serviceops_models import AIRun, now

ROUTING_MODES = {
    "smart": "Smart",
    "internal_first": "Private first",
    "balanced": "Spread the load",
    "priority": "In order",
}
EXTERNAL_SCOPES = ("never", "knowledge_only", "not_sensitive")
CIRCUIT_FAILURES = 3
CIRCUIT_SECONDS = 60
REASON_TEXT = {
    "personal": "personal details",
    "credentials": "passwords or keys",
    "financial": "payment or bank numbers",
    "custom": "a word marked as sensitive",
}

_CARD = re.compile(r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b")
_SSN = re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|pwd|passphrase|secret|api[_ -]?key|access[_ -]?key|token)\b\s*(?:is|are|[:=])\s*\S{4,}")
_SECRET_SHAPES = (
    re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"\b(?:sk|pk|ghp|gho|xox[bp])[-_][A-Za-z0-9-]{20,}"),
)


def _luhn(number):
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


def custom_terms(config):
    terms = re.split(r"[\n,]", getattr(config, "sensitive_terms", "") or "")
    return [t.strip().lower() for t in terms if t.strip()][:200]


def scan(text, config, kind=None):
    """Reasons a piece of text should stay on the organization's own AI (empty set: nothing found)."""
    text = str(text or "")
    found = set()
    # Published knowledge is written by the organization; its contact numbers are not personal details.
    if getattr(config, "detect_personal", True) and kind != "knowledge":
        if EMAIL_PATTERN.search(text) or _SSN.search(text) or any(p.search(text) for p in PHONE_PATTERNS):
            found.add("personal")
    if getattr(config, "detect_credentials", True):
        if _SECRET_ASSIGNMENT.search(text) or any(p.search(text) for p in _SECRET_SHAPES):
            found.add("credentials")
    if getattr(config, "detect_financial", True):
        if any(_luhn(m.group(0)) for m in _CARD.finditer(text)) or _IBAN.search(text.replace(" ", " ")):
            found.add("financial")
    lowered = text.lower()
    if any(term in lowered for term in custom_terms(config)):
        found.add("custom")
    return found


@dataclass
class Plan:
    candidates: list = field(default_factory=list)
    sensitive: bool = False
    reasons: list = field(default_factory=list)
    blocked: str = ""
    note: str = ""


def usable(connection):
    return bool(connection.enabled and connection.model)


def circuit_open(connection, at=None):
    at = at or now()
    last = connection.last_failure_at
    if connection.consecutive_failures < CIRCUIT_FAILURES or not last:
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=at.tzinfo)
    return at - last < timedelta(seconds=CIRCUIT_SECONDS)


def running_counts(tenant_id):
    rows = AIRun.query.filter(AIRun.tenant_id == tenant_id, AIRun.status == "running", AIRun.connection_id.isnot(None)).all()
    counts = {}
    for row in rows:
        counts[row.connection_id] = counts.get(row.connection_id, 0) + 1
    return counts


def _weighted(items, rng):
    """Random order where a heavier service tends to come first (Efraimidis-Spirakis)."""
    return sorted(items, key=lambda c: rng.random() ** (1.0 / max(1, c.weight)), reverse=True)


def external_allowed(config, sensitive, kinds):
    if not config.external_consent or config.external_scope == "never" or sensitive:
        return False
    if config.external_scope == "knowledge_only":
        return bool(kinds) and set(kinds) <= {"knowledge"}
    return True


def plan(config, connections, reasons=(), kinds=(), counts=None, rng=None, at=None):
    """Order the services that may answer this request; `blocked` explains an empty list."""
    rng = rng or random
    counts = counts or {}
    reasons = sorted(reasons)
    sensitive = bool(reasons)
    result = Plan(sensitive=sensitive, reasons=reasons)
    pool = [c for c in connections if usable(c)]
    if not pool:
        result.blocked = "no_service"
        return result
    allow_external = external_allowed(config, sensitive, kinds)
    eligible = [c for c in pool if not c.external or allow_external]
    if not eligible:
        result.blocked = "sensitive_no_private" if sensitive else "external_not_permitted"
        return result

    def has_room(c):
        return counts.get(c.id, 0) < max(1, c.max_concurrency)

    healthy = [c for c in eligible if not circuit_open(c, at)]
    pool_order = healthy or eligible  # if everything is failing, still try rather than give up silently
    mode = config.routing_mode if config.routing_mode in ROUTING_MODES else "smart"
    if mode == "priority":
        ordered = sorted(pool_order, key=lambda c: (c.priority, c.name))
    elif mode == "balanced":
        room = _weighted([c for c in pool_order if has_room(c)], rng)
        busy = sorted([c for c in pool_order if not has_room(c)], key=lambda c: counts.get(c.id, 0) / max(1, c.max_concurrency))
        ordered = room + busy
    else:  # smart and internal_first: your own AI first, external only as overflow or failover
        def tier(c):
            return (0 if not c.external else 1, 0 if has_room(c) else 1)
        groups = {}
        for c in pool_order:
            groups.setdefault(tier(c), []).append(c)
        ordered = []
        keys = sorted(groups, key=lambda k: (k[1], k[0]) if mode == "smart" else (k[0], k[1]))
        for key in keys:
            ordered.extend(_weighted(groups[key], rng) if key[1] == 0 else sorted(
                groups[key], key=lambda c: counts.get(c.id, 0) / max(1, c.max_concurrency)))
        # Smart mode: a private service with room beats an external one with room; an external one with
        # room beats a busy private one. internal_first keeps private services ahead even when busy.
    result.candidates = ordered
    if sensitive:
        listed = " and ".join(REASON_TEXT[r] for r in reasons)
        result.note = f"Kept on your organization's own AI because the request includes {listed}."
    return result


def describe(connection, plan_result, attempt=0):
    """What the person asking sees, in plain language."""
    where = "external" if connection.external else "private"
    if where == "private":
        reason = plan_result.note or "Answered by your organization's own AI."
    else:
        reason = "Answered by an external AI service. Nothing sensitive was included."
    if attempt:
        reason += " The first choice was unavailable."
    return {"name": connection.name, "location": where, "reason": reason, "sensitive": plan_result.sensitive}


BLOCKED_TEXT = {
    "sensitive_no_private": "This request includes sensitive information, so it can only be handled by your organization's own AI, and none is available right now. Please try again shortly.",
    "external_not_permitted": "Your administrator has not allowed this request to use an external AI service, and no private AI is available.",
    "no_service": "No AI service is available right now. Please ask your administrator.",
}


def record_success(connection):
    connection.consecutive_failures = 0
    connection.last_success_at = now()


def record_failure(connection):
    connection.consecutive_failures = (connection.consecutive_failures or 0) + 1
    connection.last_failure_at = now()
