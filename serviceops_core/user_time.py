"""Date and time as each person sees it.

Pages show times in the signed-in person's time zone (usertime). Forms must
read what they type in the same zone, or a change shown as 09:00-17:00 JST
expects 00:00-08:00 typed, and its tasks seem to ignore the window. Times are
stored in UTC; only input and display use the person's zone.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import has_request_context
from flask_login import current_user

INPUT_FORMAT = "%Y-%m-%dT%H:%M"  # what <input type="datetime-local"> sends and shows


def user_zone(user=None):
    """The person's zone (UTC when unknown)."""
    if user is None and has_request_context() and current_user and current_user.is_authenticated:
        user = current_user
    name = getattr(user, "timezone", None) if user is not None else None
    try:
        return ZoneInfo(name) if name else ZoneInfo("UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def parse_user_datetime(value, user=None):
    """A date-time typed in a form, read in the person's zone, as aware UTC.
    Empty input is None; a value carrying its own offset keeps it. Raises
    ValueError for anything that is not a date-time."""
    text = (value or "").strip()
    if not text:
        return None
    if len(text) > 40:
        raise ValueError("date-time too long")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=user_zone(user))
    return parsed.astimezone(timezone.utc)


def to_user(value, user=None):
    """An aware or UTC-naive moment in the person's zone."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(user_zone(user))


def input_value(value, user=None):
    """The value attribute for a datetime-local field, in the person's zone."""
    moment = to_user(value, user)
    return moment.strftime(INPUT_FORMAT) if moment else ""


def zone_label(user=None, at=None):
    """Short zone name for labels, e.g. "JST" or "UTC"."""
    moment = (at or datetime.now(timezone.utc)).astimezone(user_zone(user))
    return moment.tzname() or str(user_zone(user))


def display(value, user=None, fmt="%Y-%m-%d %H:%M"):
    """A moment for a message, in the person's zone with its zone name."""
    moment = to_user(value, user)
    return f"{moment.strftime(fmt)} {moment.tzname()}" if moment else ""
