"""Declarative role/action policy for browser and future REST surfaces."""
import json
from functools import lru_cache
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "authorization.json"


class PolicyConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_policy():
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyConfigurationError(
            f"Cannot load authorization policy {POLICY_PATH}: {error}"
        ) from error
    actions = policy.get("actions")
    roles = policy.get("roles")
    if not isinstance(actions, list) or not actions or len(actions) != len(set(actions)):
        raise PolicyConfigurationError("Authorization actions must be a unique non-empty list.")
    if not isinstance(roles, dict) or not roles:
        raise PolicyConfigurationError("Authorization roles must be a non-empty object.")
    action_set = set(actions)
    for role, grants in roles.items():
        if not isinstance(grants, list) or not set(grants).issubset(action_set):
            raise PolicyConfigurationError(f"Role {role} contains unknown actions.")
    return policy


def role_has_action(role, action):
    policy = load_policy()
    if action not in policy["actions"]:
        raise PolicyConfigurationError(f"Unknown authorization action: {action}")
    return action in policy["roles"].get(role, ())


def validate_policy():
    load_policy()
    return True
