"""Respecting provider allowances (a free tier, for example) and using them well.

Every attempt to call an AI service is logged briefly (`ai_call`). From that log ServiceOps knows, for each service,
how many requests and tokens were used in the last minute and since the daily reset, so it can (1) avoid a service
whose allowance is spent instead of waiting for the provider to refuse, (2) spread work across services in proportion
to the allowance each has left, and (3) keep scarce, more capable models for work that needs them.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import case, func

from serviceops_models import AICall, AIConnection, db, now

# Google AI Studio free-tier allowances as shown in the project's rate-limit dashboard (2026-09-21):
# (requests per minute, tokens per minute, requests per day). Google does not expose these through the API, and
# they change, so they are only starting points that an administrator can edit.
GOOGLE_HOST = "generativelanguage.googleapis.com"
_PRESETS = (
    (re.compile(r"gemma", re.I), (30, 16_000, 14_400)),
    (re.compile(r"\bpro\b|-pro", re.I), (0, 0, 0)),  # no free-tier allowance
    (re.compile(r"2\.5-flash-lite", re.I), (10, 250_000, 20)),
    (re.compile(r"flash-lite", re.I), (15, 250_000, 500)),
    (re.compile(r"flash", re.I), (5, 250_000, 20)),
)
TIER_RANK = {"lite": 0, "standard": 1, "pro": 2}


def preset_for(provider, endpoint, model):
    """Free-tier starting limits for a Google model, or None when unknown."""
    if provider != "openai_compatible" or GOOGLE_HOST not in (endpoint or ""):
        return None
    for pattern, (rpm, tpm, rpd) in _PRESETS:
        if pattern.search(model or ""):
            return {"rpm_limit": rpm, "tpm_limit": tpm, "rpd_limit": rpd, "quota_tz": "America/Los_Angeles"}
    return None


_LITE = re.compile(r"lite|gemma|(?:^|[-_/])mini(?:$|[-_])|haiku|(?:^|[-_])small", re.I)
_PRO = re.compile(r"(?:^|[-_/])pro(?:$|[-_])|opus|(?:^|[-_])large", re.I)


def tier_of(model):
    """lite (fast and cheap), standard, or pro (most capable and scarce), from the model's name."""
    name = model or ""
    if _LITE.search(name):
        return "lite"
    if _PRO.search(name):
        return "pro"
    return "standard"


def _aware(moment):
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def valid_timezone(name):
    try:
        ZoneInfo(name)
        return True
    except Exception:  # noqa: BLE001 - unknown key or missing tz database
        return False


def day_start(zone_name, at):
    zone = ZoneInfo(zone_name if valid_timezone(zone_name) else "UTC")
    local = _aware(at).astimezone(zone)
    return local.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc)


@dataclass(frozen=True)
class CallUsage:
    rpm_used: int
    tpm_used: int
    rpd_used: int
    first_minute_call: datetime | None


def recent_calls(tenant_id, at=None):
    """Exact usage in two queries, returning one aggregate per service.

    Aggregate in the database so busy tenants neither lose calls to a row
    limit nor load their entire call history into the web/worker process.
    Each service retains its own provider's local-midnight boundary.
    """
    at = _aware(at or now())
    starts = {identifier: day_start(zone or 'UTC', at) for identifier, zone in
              db.session.query(AIConnection.id, AIConnection.quota_tz).filter(
                  AIConnection.tenant_id == tenant_id)}
    if not starts:
        return {}
    minute = AICall.started_at >= at - timedelta(seconds=60)
    today = AICall.started_at >= case(starts, value=AICall.connection_id)
    rows = db.session.query(
        AICall.connection_id,
        func.count(case((minute, 1))),
        func.coalesce(func.sum(case((minute, AICall.prompt_tokens + AICall.completion_tokens), else_=0)), 0),
        func.count(case((today, 1))),
        func.min(case((minute, AICall.started_at))),
    ).filter(AICall.tenant_id == tenant_id, AICall.connection_id.in_(starts),
             AICall.started_at >= min(min(starts.values()), at - timedelta(seconds=60))).group_by(AICall.connection_id)
    return {identifier: CallUsage(rpm, tpm, rpd, first) for identifier, rpm, tpm, rpd, first in rows}


@dataclass
class Headroom:
    ok: bool = True
    score: float = 1.0  # share of the tightest allowance still available (1 = plenty, unlimited counts as 1)
    reason: str = ""  # "", "minute", "day" or "none"
    wait: int = 0  # seconds until this service can be used again
    rpm_used: int = 0
    tpm_used: int = 0
    rpd_used: int = 0
    resets_in: int = 0


def headroom(connection, calls, est_tokens=0, at=None):
    at = _aware(at or now())
    mine = calls.get(connection.id, [])
    start = day_start(connection.quota_tz or "UTC", at)
    zone = ZoneInfo(connection.quota_tz if valid_timezone(connection.quota_tz) else 'UTC')
    reset = (start.astimezone(zone) + timedelta(days=1)).astimezone(timezone.utc)
    if isinstance(mine, CallUsage):
        usage = mine
    else:
        minute = [c for c in mine if _aware(c.started_at) >= at - timedelta(seconds=60)]
        usage = CallUsage(len(minute), sum(c.prompt_tokens + c.completion_tokens for c in minute),
                          sum(_aware(c.started_at) >= start for c in mine),
                          min((_aware(c.started_at) for c in minute), default=None))
    result = Headroom(rpm_used=usage.rpm_used, tpm_used=usage.tpm_used, rpd_used=usage.rpd_used,
                      resets_in=int((reset - at).total_seconds()))
    limits = (connection.rpm_limit, connection.tpm_limit, connection.rpd_limit)
    if all(limit is None for limit in limits):
        return result
    if any(limit == 0 for limit in limits):
        result.ok, result.reason, result.score, result.wait = False, "none", 0.0, 86400
        return result
    fractions = []
    if connection.rpd_limit is not None:
        fractions.append(1 - result.rpd_used / connection.rpd_limit)
        if result.rpd_used >= connection.rpd_limit:
            result.ok, result.reason, result.wait = False, "day", result.resets_in
    if not result.reason and connection.rpm_limit is not None:
        fractions.append(1 - result.rpm_used / connection.rpm_limit)
        if result.rpm_used >= connection.rpm_limit:
            result.ok, result.reason = False, "minute"
            result.wait = max(1, int(60 - (at - _aware(usage.first_minute_call)).total_seconds()))
    if not result.reason and connection.tpm_limit is not None:
        fractions.append(1 - (result.tpm_used + est_tokens) / connection.tpm_limit)
        if result.tpm_used + est_tokens > connection.tpm_limit:
            result.ok, result.reason = False, "minute"
            result.wait = max(1, int(60 - (at - _aware(usage.first_minute_call)).total_seconds())) if usage.first_minute_call else 60
    result.score = max(0.0, min(fractions)) if fractions else 1.0
    return result


def wait_text(seconds):
    if seconds >= 3600:
        return f"about {round(seconds / 3600)} hour{'s' if round(seconds / 3600) != 1 else ''}"
    if seconds >= 90:
        return f"about {round(seconds / 60)} minutes"
    return "a minute"


def estimate_tokens(messages):
    return sum(len(m.get("content", "").encode("utf-8")) // 3 + 32 for m in messages)


def open_call(tenant_id, connection_id, prompt_tokens):
    call = AICall(tenant_id=tenant_id, connection_id=connection_id, prompt_tokens=prompt_tokens)
    db.session.add(call)
    db.session.commit()
    return call.id


def close_call(call_id, status, usage=None):
    call = db.session.get(AICall, call_id)
    if not call:
        return
    call.status = status
    if usage:
        call.prompt_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or call.prompt_tokens)
        # Hidden thinking is billed against the allowance but reported only in the total (Gemini).
        call.completion_tokens = max(int(usage.get("completion_tokens") or usage.get("output_tokens") or 0),
                                     int(usage.get("total_tokens") or 0) - call.prompt_tokens)
    db.session.commit()
