"""Restricted declarative workflow validation and evaluation."""
import hashlib
import json
from pathlib import Path

PACKAGE_PATH = Path(__file__).resolve().parent.parent / "config" / "workflows.json"
EVENTS = {
    "ticket.state_entry", "ticket.manual", "ticket.api_trigger",
    "ticket.sla_breached", "ticket.scheduled",
}
OPERATORS = {"equals", "not_equals", "in", "not_empty", "empty"}
ACTIONS = {
    "add_history", "notify_requester", "notify_team_manager", "wait",
    "run_subflow",
}
FIELDS = {
    "kind", "state", "priority", "impact", "urgency", "category",
    "sla_name", "triggered_by",
}


class WorkflowConfigurationError(RuntimeError):
    pass


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def validate_action(action, allow_subflow=True):
    if action.get("type") not in ACTIONS:
        raise WorkflowConfigurationError("Workflow action is unsupported.")
    allowed_action_fields = {
        "type", "event", "details", "title", "body", "minutes", "compensate",
        "subflow",
    }
    if set(action) - allowed_action_fields:
        raise WorkflowConfigurationError("Action contains unsupported fields.")
    compensation = action.get("compensate")
    if compensation is not None:
        if not isinstance(compensation, dict) or compensation.get("type") != "add_history":
            raise WorkflowConfigurationError("Only add_history compensation is supported.")
        if set(compensation) != {"type", "event", "details"}:
            raise WorkflowConfigurationError("Compensation action schema is invalid.")
    if action["type"] == "add_history":
        if not {"type", "event", "details"}.issubset(action):
            raise WorkflowConfigurationError("History action schema is invalid.")
    elif action["type"] == "wait":
        if set(action) != {"type", "minutes"} or not isinstance(action["minutes"], int):
            raise WorkflowConfigurationError("Wait action schema is invalid.")
        if action["minutes"] < 1 or action["minutes"] > 10080:
            raise WorkflowConfigurationError("Wait must be between 1 and 10080 minutes.")
    elif action["type"] == "run_subflow":
        if not allow_subflow or set(action) != {"type", "subflow"} or not action["subflow"]:
            raise WorkflowConfigurationError("Subflow action schema is invalid.")
    elif not {"type", "title", "body"}.issubset(action):
        raise WorkflowConfigurationError("Notification action schema is invalid.")


def validate_workflow(workflow, subflow_keys=()):
    required = {
        "key", "name", "event", "conditions", "actions",
        "rate_limit_per_minute",
    }
    if set(workflow) != required:
        raise WorkflowConfigurationError("Workflow fields do not match the supported schema.")
    if not workflow["key"] or workflow["event"] not in EVENTS:
        raise WorkflowConfigurationError("Workflow key or event is invalid.")
    if not isinstance(workflow["conditions"], list) or not isinstance(workflow["actions"], list):
        raise WorkflowConfigurationError("Workflow conditions and actions must be lists.")
    if not workflow["actions"]:
        raise WorkflowConfigurationError("Workflow must contain at least one action.")
    rate_limit = workflow["rate_limit_per_minute"]
    if not isinstance(rate_limit, int) or rate_limit < 1 or rate_limit > 1000:
        raise WorkflowConfigurationError("Workflow rate limit must be 1 through 1000.")
    for condition in workflow["conditions"]:
        if set(condition) - {"field", "operator", "value"}:
            raise WorkflowConfigurationError("Condition contains unsupported fields.")
        if condition.get("field") not in FIELDS or condition.get("operator") not in OPERATORS:
            raise WorkflowConfigurationError("Condition field or operator is unsupported.")
    for action in workflow["actions"]:
        validate_action(action)
        if action["type"] == "run_subflow" and action["subflow"] not in subflow_keys:
            raise WorkflowConfigurationError("Workflow references an unknown subflow.")
    return workflow


def validate_subflows(subflows):
    if not isinstance(subflows, dict):
        raise WorkflowConfigurationError("Subflows must be an object.")
    for key, actions in subflows.items():
        if not key or not isinstance(actions, list) or not actions:
            raise WorkflowConfigurationError("Every subflow needs a key and actions.")
        for action in actions:
            validate_action(action)
            if action["type"] == "run_subflow" and action["subflow"] not in subflows:
                raise WorkflowConfigurationError("Subflow references an unknown subflow.")
    visiting, visited = set(), set()

    def visit(key):
        if key in visiting:
            raise WorkflowConfigurationError("Subflow dependency cycle detected.")
        if key in visited:
            return
        visiting.add(key)
        for action in subflows[key]:
            if action["type"] == "run_subflow":
                visit(action["subflow"])
        visiting.remove(key)
        visited.add(key)

    for key in subflows:
        visit(key)
    return subflows


def materialize_actions(actions, subflows):
    result = []
    for action in actions:
        if action["type"] == "run_subflow":
            result.extend(materialize_actions(subflows[action["subflow"]], subflows))
        else:
            result.append(action)
    return result


def materialize_workflow(workflow, subflows):
    rendered = dict(workflow)
    rendered["actions"] = materialize_actions(workflow["actions"], subflows)
    return rendered


def load_workflow_package():
    try:
        package = json.loads(PACKAGE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise WorkflowConfigurationError(f"Cannot load workflow package: {error}") from error
    if package.get("schema_version") not in (1, 2) or not isinstance(package.get("workflows"), list):
        raise WorkflowConfigurationError("Unsupported workflow package schema.")
    subflows = validate_subflows(package.get("subflows", {}))
    keys = []
    for workflow in package["workflows"]:
        validate_workflow(workflow, subflows)
        keys.append(workflow["key"])
    if len(keys) != len(set(keys)):
        raise WorkflowConfigurationError("Workflow keys must be unique.")
    return package


def package_digest(package):
    return hashlib.sha256(canonical_json(package).encode()).hexdigest()


def condition_matches(condition, context):
    actual = context.get(condition["field"])
    operator = condition["operator"]
    expected = condition.get("value")
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "in":
        return actual in expected if isinstance(expected, list) else False
    if operator == "empty":
        return actual in (None, "")
    if operator == "not_empty":
        return actual not in (None, "")
    return False


def workflow_matches(workflow, event, context):
    return workflow["event"] == event and all(
        condition_matches(condition, context) for condition in workflow["conditions"]
    )
