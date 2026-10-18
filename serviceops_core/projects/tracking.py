"""Time tracking (B-449): Jira-style durations, work logs, and the original,
remaining and spent estimates on a work item.

Durations are written like Jira's: "1w 2d 3h 30m", "2h", "45m" or "1.5h".
A day and a week are the tenant's working day and week
(PROJECTS_HOURS_PER_DAY, PROJECTS_DAYS_PER_WEEK).
"""
import re
from datetime import datetime

from flask import abort
from sqlalchemy import func

import app as core
from serviceops_core.localization import tr
from serviceops_core.projects import service
from serviceops_core.projects.models import WorkItem, WorkItemWorklog
from serviceops_models import db, now

# Bounded digits: an unbounded number became float("inf") and crashed round() with a 500.
DURATION_TOKEN = re.compile(r"(\d{1,9}(?:\.\d{1,6})?)\s*([wdhm])\s*")
MAX_MINUTES = 10 ** 7
REMAINING_MODES = ("auto", "leave", "new", "reduce")


def hours_per_day():
    value = core.setting_int("PROJECTS_HOURS_PER_DAY", 8)
    return value if 1 <= value <= 24 else 8


def days_per_week():
    value = core.setting_int("PROJECTS_DAYS_PER_WEEK", 5)
    return value if 1 <= value <= 7 else 5


def parse_duration(text, label=None):
    """Minutes for a Jira duration; None for blank. A bare number means hours."""
    label = label or tr("Time")
    text = str(text or "").strip().lower()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        text += "h"
    # Walk the parts anchored at the current position: linear time, where a repeated group with optional
    # spaces on both sides backtracked polynomially on long input.
    parts, position = [], 0
    while position < len(text):
        part = DURATION_TOKEN.match(text, position)
        if not part:
            abort(400, description=tr("{label}: write a duration such as 2h 30m, 1d or 1w.", label=label))
        parts.append((part.group(1), part.group(2)))
        position = part.end()
    unit = {"m": 1, "h": 60, "d": 60 * hours_per_day(), "w": 60 * hours_per_day() * days_per_week()}
    minutes = round(sum(float(amount) * unit[kind] for amount, kind in parts))
    if minutes > MAX_MINUTES:
        abort(400, description=tr("{label} is too long.", label=label))
    return minutes


def format_duration(minutes):
    """"1w 2d 3h 30m" (largest units first, zero parts left out); "0m" for zero."""
    if minutes is None:
        return ""
    minutes = int(minutes)
    if minutes == 0:
        return "0m"
    day, week = 60 * hours_per_day(), 60 * hours_per_day() * days_per_week()
    parts = []
    for size, suffix in ((week, "w"), (day, "d"), (60, "h"), (1, "m")):
        if minutes >= size:
            parts.append(f"{minutes // size}{suffix}")
            minutes %= size
    return " ".join(parts)


def _recalculate_spent(item):
    item.spent_minutes = int(db.session.query(func.coalesce(func.sum(WorkItemWorklog.minutes), 0)).filter(
        WorkItemWorklog.work_item_id == item.id).scalar())


def _apply_remaining(item, mode, spent, new_value, reduce_by):
    if mode not in REMAINING_MODES:
        abort(400, description=tr("Choose how to adjust the remaining estimate."))
    if mode == "auto":
        base = item.remaining_minutes if item.remaining_minutes is not None else item.estimate_minutes
        if base is not None:
            item.remaining_minutes = max(0, base - spent)
    elif mode == "new":
        item.remaining_minutes = parse_duration(new_value, tr("Remaining estimate")) or 0
    elif mode == "reduce":
        amount = parse_duration(reduce_by, tr("Reduce by")) or 0
        base = item.remaining_minutes if item.remaining_minutes is not None else (item.estimate_minutes or 0)
        item.remaining_minutes = max(0, base - amount)


def _started(value):
    if not value:
        return now()
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        abort(400, description=tr("Date started must be a date and time."))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=now().tzinfo)
    return parsed


def _lock_item(item, actor):
    # Every work-log mutation recalculates counters on the same parent row.
    # Refresh after locking so an earlier request's remaining estimate is
    # not reused after another request has committed its work log.
    from serviceops_core.projects.models import Project
    project_id, tenant_id = item.project_id, item.tenant_id
    with db.session.no_autoflush:
        Project.query.filter_by(id=project_id).with_for_update().populate_existing().one()
        WorkItem.query.with_entities(WorkItem.id).filter_by(id=item.id).with_for_update().one()
        db.session.refresh(item, [column.key for column in WorkItem.__table__.columns])
        if item.project_id != project_id or item.tenant_id != tenant_id:
            abort(409, description=tr("This work item moved to another project. Reload it before making changes."))
        db.session.expire(item, ['project', 'status'])
    service._forget_roles()
    service.require_edit(actor, item.project)
    return item


def log_work(actor, item, spent, started=None, comment="", remaining_mode="auto", new_remaining=None,
             reduce_by=None):
    service.require_edit(actor, item.project)
    _lock_item(item, actor)
    minutes = parse_duration(spent, tr("Time spent"))
    if not minutes:
        abort(400, description=tr("Enter the time spent, for example 1h 30m."))
    comment = (comment or "").strip()
    if len(comment) > 10000:
        abort(400, description=tr("A work log comment can have at most 10000 characters."))
    worklog = WorkItemWorklog(tenant_id=item.tenant_id, work_item_id=item.id, author_id=actor.id,
                              started_at=_started(started), minutes=minutes, comment=comment)
    db.session.add(worklog)
    db.session.flush()
    _apply_remaining(item, remaining_mode, minutes, new_remaining, reduce_by)
    _recalculate_spent(item)
    item.updated_at = now()
    service.log_work_item_history(item, actor, "work logged", None, format_duration(minutes))
    from serviceops_core.projects import sprints
    sprints.capture(actor, item)
    return worklog


def _own_or_admin(actor, item, worklog):
    if worklog.author_id != actor.id and not service.can_administer(actor, item.project):
        abort(403, description=tr("Only the author or a project administrator can change this work log."))
    service.require_edit(actor, item.project)


def update_worklog(actor, item, worklog, spent=None, started=None, comment=None):
    _own_or_admin(actor, item, worklog)
    _lock_item(item, actor)
    worklog = worklog_or_404(item, worklog.id)
    if spent is not None:
        minutes = parse_duration(spent, tr("Time spent"))
        if not minutes:
            abort(400, description=tr("Enter the time spent, for example 1h 30m."))
        worklog.minutes = minutes
    if started is not None:
        worklog.started_at = _started(started)
    if comment is not None:
        worklog.comment = comment.strip()[:10000]
    worklog.updated_at = now()
    _recalculate_spent(item)
    service.log_work_item_history(item, actor, "work log edited", None, format_duration(worklog.minutes))
    from serviceops_core.projects import sprints
    sprints.capture(actor, item)


def delete_worklog(actor, item, worklog):
    _own_or_admin(actor, item, worklog)
    _lock_item(item, actor)
    worklog = worklog_or_404(item, worklog.id)
    minutes = worklog.minutes
    db.session.delete(worklog)
    db.session.flush()
    _recalculate_spent(item)
    service.log_work_item_history(item, actor, "work log deleted", format_duration(minutes), None)
    from serviceops_core.projects import sprints
    sprints.capture(actor, item)


def worklog_or_404(item, worklog_id):
    worklog = WorkItemWorklog.query.filter_by(id=worklog_id, work_item_id=item.id).populate_existing().first()
    if not worklog:
        abort(404)
    return worklog


def time_tracking(item):
    """Figures for the time tracking panel: minutes and percentages of the
    larger of the original estimate and spent + remaining."""
    estimate = item.estimate_minutes or 0
    remaining = item.remaining_minutes if item.remaining_minutes is not None else estimate
    spent = item.spent_minutes or 0
    scale = max(estimate, spent + remaining, 1)
    return {"estimate": estimate, "remaining": remaining, "spent": spent,
            "estimate_pct": round(estimate * 100 / scale), "spent_pct": round(spent * 100 / scale),
            "remaining_pct": round(remaining * 100 / scale),
            "has_any": bool(item.estimate_minutes or spent or item.remaining_minutes)}


def worklogs_for(item):
    return WorkItemWorklog.query.filter_by(work_item_id=item.id).order_by(WorkItemWorklog.started_at.desc()).all()


