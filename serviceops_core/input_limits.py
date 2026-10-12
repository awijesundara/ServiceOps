"""Turn malformed text input into a clear 400 instead of a database error.

PostgreSQL rejects NUL characters in text and values longer than a column's
declared length; both used to surface as 500 errors from whichever handler
happened to save the value. `reject_nul_characters` runs before every request
and `_check_lengths` runs before every flush made while serving a request
(background jobs keep their own handling).
"""
from flask import abort, has_request_context, request
from sqlalchemy import String, event
from sqlalchemy.orm import Session
from werkzeug.exceptions import BadRequest

from serviceops_core.localization import tr

_MAX_JSON_SCAN = 2_000_000


class ValueTooLong(BadRequest):
    pass


def _has_nul(value, depth=0):
    if isinstance(value, str):
        return "\x00" in value
    if depth > 20:
        return False
    if isinstance(value, dict):
        return any(_has_nul(k, depth + 1) or _has_nul(v, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_nul(item, depth + 1) for item in value)
    return False


def reject_nul_characters():
    """before_request hook: a NUL character is never valid text input."""
    values = list(request.args.values()) + list(request.args.keys())
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data"):
            values += list(request.form.values()) + list(request.form.keys())
            values += [f.filename or "" for f in request.files.values()]
        elif request.is_json and (request.content_length or 0) <= _MAX_JSON_SCAN:
            values.append(request.get_json(silent=True))
    if any(_has_nul(value) for value in values):
        abort(400, description=tr("The request contains a character that is not allowed (NUL)."))


@event.listens_for(Session, "before_flush")
def _check_lengths(session, flush_context, instances):
    if not has_request_context():
        return
    for obj in list(session.new) + list(session.dirty):
        table = getattr(obj, "__table__", None)
        if table is None:
            continue
        for column in table.columns:
            limit = getattr(column.type, "length", None)
            if not limit or not isinstance(column.type, String):
                continue
            value = getattr(obj, column.key, None) if hasattr(obj, column.key) else None
            if isinstance(value, str) and len(value) > limit:
                label = column.key.replace("_", " ")
                raise ValueTooLong(description=tr("{field} is too long: use at most {limit} characters.",
                                                  field=label[:1].upper() + label[1:], limit=limit))
