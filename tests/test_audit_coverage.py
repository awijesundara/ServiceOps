"""Static-analysis test for audit-log coverage (ITIL 4 gap-analysis
P1 item): every mutating route either writes to the tamper-evident Audit
trail (directly or via a helper it calls), logs to the per-record
TaskHistory, or -- for routes that only touch the caller's own personal/
UI-preference data with no shared-record compliance impact -- is
explicitly allowlisted here with a reason.

This exists so "how do you know every state-changing action is logged"
has an answer better than good-faith practice: a route with neither kind
of logging, and not on the allowlist, fails CI.
"""
import ast
from pathlib import Path

APP_PY = Path(__file__).resolve().parent.parent / "app.py"

ALLOWLIST = {
    "notification_mark_read": "marks the caller's own notification read; no shared record changes",
    "notifications_mark_all_read": "marks the caller's own notifications read; no shared record changes",
    "notifications_clear": "deletes the caller's own notifications; no shared record changes",
    "favorite_toggle": "toggles the caller's own bookmark; no shared record changes",
    "history_record": "records the caller's own recently-viewed pages; no shared record changes",
    "set_acting_role": "switches which of the caller's own already-granted roles this session acts as; no shared record changes, and only ever narrows/restores the caller's own authority",
}

LOGGING_CALLS = {"audit", "log_history", "log_field_changes"}


def _decorator_call_name(dec):
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _decorator_methods(dec):
    name = _decorator_call_name(dec)
    if name == "post":
        return {"POST"}
    if name == "put":
        return {"PUT"}
    if name == "delete":
        return {"DELETE"}
    if name == "route" and isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg == "methods":
                try:
                    return {elt.value for elt in kw.value.elts}
                except AttributeError:
                    return set()
    return set()


def _direct_calls(func_node):
    names = set()
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
    return names


def test_every_mutating_route_logs_to_audit_or_history_or_is_allowlisted():
    tree = ast.parse(APP_PY.read_text())
    functions = {}
    mutating_routes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = node
            methods = set()
            for dec in node.decorator_list:
                methods |= _decorator_methods(dec)
            if methods & {"POST", "PUT", "DELETE", "PATCH"}:
                mutating_routes.append(node)

    def logs(func_node, seen=None):
        seen = seen if seen is not None else set()
        if func_node.name in seen:
            return False
        seen.add(func_node.name)
        calls = _direct_calls(func_node)
        if calls & LOGGING_CALLS:
            return True
        return any(
            (callee := functions.get(name)) is not None and logs(callee, seen)
            for name in calls
        )

    missing = sorted(
        route.name for route in mutating_routes
        if route.name not in ALLOWLIST and not logs(route)
    )
    assert not missing, (
        "These mutating routes have no audit()/log_history() call, directly or via a "
        "helper they call -- either add one, or add the route to ALLOWLIST in "
        f"tests/test_audit_coverage.py with a reason: {missing}"
    )

    route_names = {route.name for route in mutating_routes}
    stale = sorted(name for name in ALLOWLIST if name not in route_names)
    assert not stale, (
        f"ALLOWLIST entries in tests/test_audit_coverage.py no longer match a "
        f"mutating route (renamed or removed?): {stale}"
    )
