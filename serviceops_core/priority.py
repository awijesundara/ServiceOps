"""Declarative impact/urgency priority policy."""
import json
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "priority_matrix.json"


class PriorityConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_priority_policy():
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PriorityConfigurationError(f"Cannot load priority policy: {error}") from error
    levels = policy.get("levels")
    matrix = policy.get("matrix")
    if not isinstance(levels, list) or not levels or len(levels) != len(set(levels)):
        raise PriorityConfigurationError("Priority levels must be unique and non-empty.")
    if set(matrix or {}) != set(levels):
        raise PriorityConfigurationError("Priority matrix must contain every impact level.")
    for impact in levels:
        row = matrix[impact]
        if set(row) != set(levels) or not set(row.values()).issubset({"P1", "P2", "P3", "P4"}):
            raise PriorityConfigurationError(f"Invalid priority row for {impact}.")
    return policy


def calculate_priority(impact, urgency):
    policy = load_priority_policy()
    try:
        return policy["matrix"][impact][urgency]
    except KeyError as error:
        raise ValueError("Impact and urgency must be Critical, High, Medium or Low.") from error


def validate_priority_policy():
    load_priority_policy()
    return True
