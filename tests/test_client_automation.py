"""serviceops_core.client_automation: the Client Management trigger engine
(condition_matches, validate_trigger). Exercised directly, isolated from
Flask/DB fixtures -- app-level wiring (evaluate_client_triggers) is covered
by tests/test_app.py's test_client_trigger_fires_matching_condition_and_skips_non_matching.
"""
import pytest

from serviceops_core.client_automation import (
    condition_matches, validate_trigger, ClientTriggerConfigurationError,
)


@pytest.mark.parametrize("field,op,value,context,expected", [
    ("priority", "eq", "Urgent", {"priority": "Urgent"}, True),
    ("priority", "eq", "Urgent", {"priority": "Normal"}, False),
    ("priority", "ne", "Urgent", {"priority": "Normal"}, True),
    ("subject", "contains", "outage", {"subject": "Major OUTAGE reported"}, True),
    ("subject", "contains", "outage", {"subject": "Billing question"}, False),
    ("channel", "starts_with", "Ph", {"channel": "Phone"}, True),
    ("tags", "is_empty", "", {"tags": ""}, True),
    ("tags", "is_empty", "", {"tags": "vip"}, False),
    ("tags", "is_not_empty", "", {"tags": "vip"}, True),
    ("status", "eq", "New", {}, False),  # missing context field -> empty string, no match
])
def test_condition_matches_operators(field, op, value, context, expected):
    assert condition_matches(field, op, value, context) is expected


def test_condition_matches_fails_closed_on_unknown_field_or_operator():
    """An unknown field/op must never silently match everything -- a
    trigger row referencing a vocabulary that's since changed should do
    nothing, not fire unpredictably."""
    assert condition_matches("not_a_real_field", "eq", "x", {"not_a_real_field": "x"}) is False
    assert condition_matches("priority", "not_a_real_op", "x", {"priority": "x"}) is False


def test_validate_trigger_accepts_a_well_formed_rule():
    assert validate_trigger("created", "priority", "eq", "add_tag", "escalated") is None


@pytest.mark.parametrize("event,field,op,action_type,value", [
    ("not_an_event", "priority", "eq", "add_tag", "x"),
    ("created", "not_a_field", "eq", "add_tag", "x"),
    ("created", "priority", "not_an_op", "add_tag", "x"),
    ("created", "priority", "eq", "not_an_action", "x"),
    ("created", "priority", "eq", "set_status", "Not A Real Status"),
    ("created", "priority", "eq", "set_priority", "Not A Real Priority"),
    ("created", "priority", "eq", "assign_to_group", ""),
    ("created", "priority", "eq", "add_tag", ""),
])
def test_validate_trigger_rejects_invalid_rules(event, field, op, action_type, value):
    with pytest.raises(ClientTriggerConfigurationError):
        validate_trigger(event, field, op, action_type, value)
