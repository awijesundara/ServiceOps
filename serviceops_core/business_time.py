"""Timezone-aware business-calendar arithmetic using the standard library."""
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class BusinessCalendarError(ValueError):
    pass


def validate_calendar(timezone_name, weekdays, start_time, end_time):
    try:
        ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as error:
        raise BusinessCalendarError("Unknown IANA timezone.") from error
    if not weekdays or not set(weekdays).issubset(set(range(7))):
        raise BusinessCalendarError("Business weekdays must be numbers 0 through 6.")
    if start_time >= end_time:
        raise BusinessCalendarError("Business start time must be before end time.")


def add_business_minutes(start, minutes, calendar, holidays=()):
    if minutes < 1:
        raise BusinessCalendarError("SLA duration must be positive.")
    zone = ZoneInfo(calendar.timezone_name)
    weekdays = set(calendar.weekdays)
    holiday_dates = set(holidays)
    cursor = start.astimezone(zone).replace(second=0, microsecond=0)
    remaining = minutes
    while remaining:
        day_open = datetime.combine(cursor.date(), calendar.start_time, tzinfo=zone)
        day_close = datetime.combine(cursor.date(), calendar.end_time, tzinfo=zone)
        if cursor.date() in holiday_dates or cursor.weekday() not in weekdays or cursor >= day_close:
            cursor = (datetime.combine(cursor.date(), calendar.start_time, tzinfo=zone)
                      + timedelta(days=1))
            continue
        if cursor < day_open:
            cursor = day_open
        usable = int((day_close - cursor).total_seconds() // 60)
        if remaining <= usable:
            return (cursor + timedelta(minutes=remaining)).astimezone(timezone.utc)
        remaining -= usable
        cursor = day_open + timedelta(days=1)
    return cursor.astimezone(timezone.utc)
