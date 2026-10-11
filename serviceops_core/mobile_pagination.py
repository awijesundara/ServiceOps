"""Bounded, signed keyset pagination for permission-filtered mobile lists."""
from datetime import datetime

from flask import abort, current_app, g, request
from itsdangerous import BadData, URLSafeSerializer
from sqlalchemy import and_, or_


def paginate(query, ordering):
    """Apply [(SQL column, descending, row accessor, value type), ...].

    Cursors belong to one user, tenant, endpoint and search. Authorization is
    still applied to the query on every page; a cursor grants no access.
    """
    raw_limit = request.args.get("limit", "100")
    if len(raw_limit) > 3 or not raw_limit.isascii() or not raw_limit.isdecimal() or not 1 <= int(raw_limit) <= 100:
        abort(400, description="limit must be an integer between 1 and 100.")
    limit = int(raw_limit)
    scope = [g.api_user.tenant_id, g.api_user.id, request.path, request.args.get("q", "").strip()]
    signer = URLSafeSerializer(current_app.config["SECRET_KEY"], salt="serviceops-mobile-page-v1")
    token = request.args.get("cursor", "")
    if token:
        try:
            if len(token) > 4096:
                raise ValueError("Oversized cursor")
            payload = signer.loads(token)
            if payload["scope"] != scope or len(payload["values"]) != len(ordering):
                raise ValueError("Cursor scope mismatch")
            values = []
            for value, (_, _, _, kind) in zip(payload["values"], ordering):
                if kind is datetime:
                    if not isinstance(value, str):
                        raise ValueError("Invalid date")
                    value = datetime.fromisoformat(value)
                elif type(value) is not kind:
                    raise ValueError("Invalid cursor value")
                values.append(value)
        except (BadData, ValueError, TypeError, KeyError):
            abort(400, description="Invalid cursor for this list.")
        terms = []
        for index, ((column, descending, _, _), value) in enumerate(zip(ordering, values)):
            prefix = [ordering[n][0] == values[n] for n in range(index)]
            terms.append(and_(*prefix, column < value if descending else column > value))
        query = query.filter(or_(*terms))
    query = query.order_by(*(column.desc() if descending else column.asc()
                             for column, descending, _, _ in ordering))
    found = query.limit(limit + 1).all()
    rows = found[:limit]
    has_more = len(found) > limit
    next_cursor = None
    if has_more:
        values = [accessor(rows[-1]) for _, _, accessor, _ in ordering]
        next_cursor = signer.dumps({"scope": scope, "values": [
            value.isoformat() if isinstance(value, datetime) else value for value in values
        ]})
    return rows, {"limit": limit, "returned": len(rows), "has_more": has_more, "next_cursor": next_cursor}
