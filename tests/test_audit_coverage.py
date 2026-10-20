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

ROOT = Path(__file__).resolve().parent.parent
# Routes live in serviceops_core/web/ and the helpers they call mostly in
# app.py, so both are parsed into one call graph.
SOURCE_FILES = [ROOT / "app.py", *sorted((ROOT / "serviceops_core" / "web").glob("*.py")),
                # Project routes delegate to their rules modules (B-443, B-449).
                *[ROOT / "serviceops_core" / "projects" / f"{name}.py"
                  for name in ("service", "tracking", "operations", "releases", "catalog", "roadmap", "planning_routes", "advanced_plans", "advanced_routes", "automation", "content", "content_routes")],
                # Approval policies (B-460) and request withdrawal (B-461) audit in their rules modules.
                ROOT / "serviceops_core" / "approval_policies.py", ROOT / "serviceops_core" / "request_withdrawal.py",
                # Dashboards (B-464) audit in their rules module.
                ROOT / "serviceops_core" / "dashboards.py",
                # Incident handling and parent/child incidents audit in their rules modules.
                ROOT / "serviceops_core" / "incident_handling.py", ROOT / "serviceops_core" / "incident_hierarchy.py"]

ALLOWLIST = {
    "planning_view_settings": "updates only the caller's project display preferences; no shared work changes",
    "api_planning_preferences": "updates only the caller's project display preferences; no shared work changes",
    "notification_mark_read": "marks the caller's own notification read; no shared record changes",
    "notifications_mark_all_read": "marks the caller's own notifications read; no shared record changes",
    "notifications_clear": "deletes the caller's own notifications; no shared record changes",
    "api_mobile_notification_read": "marks the caller's own notification read; no shared record changes",
    "api_mobile_notifications_read_all": "marks the caller's own notifications read; no shared record changes",
    "favorite_toggle": "toggles the caller's own bookmark; no shared record changes",
    "history_record": "records the caller's own recently-viewed pages; no shared record changes",
    "set_acting_role": "switches which of the caller's own already-granted roles this session acts as; no shared record changes, and only ever narrows/restores the caller's own authority",
    "guided_tours_progress": "records the caller's own dismiss/completion state for a guided tour; no shared record changes",
    "api_passkey_registration_options": "creates a short-lived one-time protocol challenge; successful credential registration is audited on completion",
    "item_watch": "starts or stops the caller's own notifications for a work item; no shared record changes",
    "item_star": "stars or unstars a work item for the caller's own Your work list; no shared record changes",
    "project_star": "stars or unstars a project for the caller's own Your work list; no shared record changes",
    "item_vote": "adds or removes the caller's own vote, which is shown as a count; no record field changes",
    "api_item_vote": "adds or removes the acting user's own vote, shown as a count; no record field changes",
    "item_comment_react": "adds or removes the caller's own emoji reaction on a comment; no record field changes",
    "markdown_preview": "renders text for the editor preview; nothing is stored",
    "api_passkey_authentication_options": "creates an unauthenticated short-lived one-time protocol challenge; successful login is audited on completion",
}

LOGGING_CALLS = {"audit", "log_history", "log_field_changes", "log_work_item_history"}


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
    functions = {}
    mutating_routes = []
    nodes = [node for path in SOURCE_FILES for node in ast.walk(ast.parse(path.read_text()))]
    assert len(SOURCE_FILES) > 2, "serviceops_core/web/ route modules not found"
    for node in nodes:
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
