"""Operator-controlled deployment kill switches for risky capabilities."""

import json
import os


def configured_feature_flags() -> dict[str, bool]:
    raw = os.getenv("FEATURE_FLAGS", "{}")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(key): enabled for key, enabled in value.items() if isinstance(enabled, bool)}


def feature_enabled(name: str, *, default: bool = False) -> bool:
    """Return a strict boolean flag; malformed or non-boolean input is ignored."""
    return configured_feature_flags().get(name, default)
