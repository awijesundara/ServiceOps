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
from serviceops_models import AIRun, db, now

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
    "customer_content": "customer support content",
    "service_request_content": "service request details",
    "restricted_record": "a restricted operational record",
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
    retry_after: int = 0  # seconds until a service with an allowance can be used again


def usable(connection):
    cooling = getattr(connection, "cooldown_until", None)
    if cooling is not None:
        cooling = cooling if cooling.tzinfo else cooling.replace(tzinfo=now().tzinfo)
        if cooling > now():
            return False  # the provider just refused us for going too fast; give it a moment
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
    rows = db.session.query(AIRun.connection_id, db.func.count()).filter(
        AIRun.tenant_id == tenant_id, AIRun.status == "running", AIRun.connection_id.isnot(None)).group_by(AIRun.connection_id).all()
    return {connection_id: total for connection_id, total in rows}


def _share(connection, head):
    found = (head or {}).get(connection.id)
    return max(0.05, found.score) if found else 1.0


def _weighted(items, rng, head=None):
    """Random order where a heavier service, and one with more of its allowance left, tends to come first
    (Efraimidis-Spirakis). Spreading in proportion to what is left uses every allowance and spares none."""
    return sorted(items, key=lambda c: rng.random() ** (1.0 / (max(1, c.weight) * _share(c, head))), reverse=True)


def _ranked(items, rng, head, prefer):
    """Economy work (chat) goes to the lighter, more plentiful models first; quality work (investigations) to the
    more capable ones first. A model nearly out of allowance steps aside so the scarce ones last the day."""
    from serviceops_core.ai import quota

    def order(c):
        base = quota.TIER_RANK[quota.tier_of(c.model)]
        base = -base if prefer == "quality" else base
        return base + (1.5 if _share(c, head) <= 0.1 else 0)
    weighted = _weighted(items, rng, head)
    return sorted(weighted, key=order)  # stable: the random weighted order breaks ties


def external_allowed(config, sensitive, kinds):
    if not config.external_consent or config.external_scope == "never" or sensitive:
        return False
    if config.external_scope == "knowledge_only":
        return bool(kinds) and set(kinds) <= {"knowledge"}
    return True


def plan(config, connections, reasons=(), kinds=(), counts=None, rng=None, at=None, headroom=None, prefer="economy",
        prefer_connection_id=None):
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

    head = headroom or {}
    open_now = [c for c in eligible if head.get(c.id) is None or head[c.id].ok]
    if not open_now:
        result.blocked = "quota"
        result.retry_after = min((head[c.id].wait for c in eligible if head.get(c.id)), default=60)
        return result
    healthy = [c for c in open_now if not circuit_open(c, at)]
    pool_order = healthy or open_now  # if everything is failing, still try rather than give up silently
    mode = config.routing_mode if config.routing_mode in ROUTING_MODES else "smart"
    if mode == "priority":
        ordered = sorted(pool_order, key=lambda c: (c.priority, c.name))
    elif mode == "balanced":
        room = _weighted([c for c in pool_order if has_room(c)], rng, head)
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
            ordered.extend(_ranked(groups[key], rng, head, prefer) if key[1] == 0 else sorted(
                groups[key], key=lambda c: counts.get(c.id, 0) / max(1, c.max_concurrency)))
        # Smart mode: a private service with room beats an external one with room; an external one with
        # room beats a busy private one. internal_first keeps private services ahead even when busy.
    if prefer_connection_id:
        # A pure reorder of `ordered`, itself already derived from `eligible` (the
        # post-privacy-gate list) -- a preferred connection the sensitivity gate
        # excluded simply isn't in `ordered` and this is a no-op for it. This must
        # never become a second way into the candidate pool.
        ordered = sorted(ordered, key=lambda c: c.id != prefer_connection_id)
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
    return {"name": connection.name, "model": connection.model, "location": where, "reason": reason,
            "sensitive": plan_result.sensitive}


def blocked_message(code, retry_after=0):
    if code == "quota":
        return ("The AI allowance is used up for now. It should be available again in "
                f"{__import__('serviceops_core.ai.quota', fromlist=['wait_text']).wait_text(retry_after)}. Please try again then.")
    return BLOCKED_TEXT.get(code, BLOCKED_TEXT["no_service"])


BLOCKED_TEXT = {
    "provider_busy": "The AI service is busy right now. Please try again in a moment.",
    "provider_key": "The AI service turned down its access key. Please let your administrator know.",
    "provider_model": "The AI model is not available. Please let your administrator know.",
    "sensitive_no_private": "This request includes sensitive information, so it can only be handled by your organization's own AI, and none is available right now. Please try again shortly.",
    "external_not_permitted": "Your administrator has not allowed this request to use an external AI service, and no private AI is available.",
    "no_service": "No AI service is available right now. Please ask your administrator.",
}

RUN_ERROR_TEXT = {
    "provider_failed": (
        "The selected AI services did not answer successfully. Try again shortly. "
        "If this continues, ask an administrator to check AI service health."
    ),
    "worker_interrupted": "The AI worker was interrupted before it finished. Please try again.",
}


def usage_today(tenant_id):
    """Requests and tokens used so far today (UTC), per service and in total. What ServiceOps itself sent:
    providers do not report a remaining quota for an API key."""
    import json
    start = now().replace(hour=0, minute=0, second=0, microsecond=0)
    per, total = {}, {"requests": 0, "tokens": 0}
    for connection_id, usage in db.session.query(AIRun.connection_id, AIRun.usage_json).filter(
            AIRun.tenant_id == tenant_id, AIRun.created_at >= start, AIRun.status == "completed").limit(5000):
        try:
            data = json.loads(usage or "{}")
        except ValueError:
            data = {}
        tokens = int(data.get("total_tokens") or 0) or int(data.get("prompt_tokens") or data.get("input_tokens") or 0) + int(
            data.get("completion_tokens") or data.get("output_tokens") or 0)
        slot = per.setdefault(connection_id, {"requests": 0, "tokens": 0})
        slot["requests"] += 1
        slot["tokens"] += tokens
        total["requests"] += 1
        total["tokens"] += tokens
    return per, total


def record_success(connection):
    connection.consecutive_failures = 0
    connection.cooldown_until = None
    connection.last_success_at = now()


def record_failure(connection, rate_limited=False):
    if rate_limited:  # being told to slow down is not a fault: pause the service briefly, keep its health record clean
        connection.cooldown_until = now() + timedelta(seconds=65)
        return
    connection.consecutive_failures = (connection.consecutive_failures or 0) + 1
    connection.last_failure_at = now()
