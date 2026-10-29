"""Turn malformed text input into a clear 400 instead of a database error.

PostgreSQL rejects NUL characters in text and values longer than a column's
declared length; both used to surface as 500 errors from whichever handler
happened to save the value. `reject_nul_characters` runs before every request
and `_check_lengths` runs before every flush made while serving a request
(background jobs keep their own handling).
"""
from itertools import chain

from flask import abort, has_request_context, request
from sqlalchemy import String, event, inspect
from sqlalchemy.orm import Session
from werkzeug.exceptions import BadRequest

from serviceops_core.localization import tr

class ValueTooLong(BadRequest):
    pass


def _has_nul(value):
    # Iterator frames keep memory proportional to depth, even for large arrays.
    frames = [iter((value,))]
    while frames:
        try:
            item = next(frames[-1])
        except StopIteration:
            frames.pop()
            continue
        if isinstance(item, str) and "\x00" in item:
            return True
        if isinstance(item, (dict, list)):
            if len(frames) > 100:
                raise BadRequest(description="The JSON request is nested too deeply.")
            frames.append(iter(chain(item.keys(), item.values())) if isinstance(item, dict) else iter(item))
    return False


def reject_nul_characters():
    """before_request hook: a NUL character is never valid text input."""
    values = [value for _, value in request.args.items(multi=True)] + list(request.args.keys())
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data"):
            values += [value for _, value in request.form.items(multi=True)] + list(request.form.keys())
            values += [f.filename or "" for _, f in request.files.items(multi=True)]
        elif request.is_json:
            try:
                # Syntax errors belong to the endpoint protocol (for example JSON-RPC).
                values.append(request.get_json(silent=True))
            except RecursionError:
                abort(400, description="The JSON request is nested too deeply.")
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
        state = inspect(obj)
        for column in table.columns:
            limit = getattr(column.type, "length", None)
            if not limit or not isinstance(column.type, String) or column.key not in state.attrs:
                continue
            # Only values being written: an existing row that already holds a
            # longer value (SQLite and IPFS mode do not enforce lengths) must
            # stay editable in its other fields.
            if not state.pending and not state.attrs[column.key].history.has_changes():
                continue
            value = state.attrs[column.key].value
            if isinstance(value, str) and len(value) > limit:
                label = column.key.replace("_", " ")
                raise ValueTooLong(description=tr("{field} is too long: use at most {limit} characters.",
                                                  field=label[:1].upper() + label[1:], limit=limit))
