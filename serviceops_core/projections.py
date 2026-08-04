"""Fail-closed Git-backed field projection policy."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "field_projections.json"
EXPECTED_SCHEMA = "serviceops.field-projections.v1"
KNOWN_ROLES = {"requester", "agent", "manager", "admin", "superadmin"}
MACHINE_AUDIENCES = {"monitoring_source"}


class ProjectionConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_projection_policy() -> dict[str, Any]:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProjectionConfigurationError(
            f"Cannot load field-projection policy: {error}"
        ) from error
    validate_projection_policy(policy)
    return policy


def validate_projection_policy(policy: dict[str, Any] | None = None) -> bool:
    if policy is None:
        try:
            policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ProjectionConfigurationError(
                f"Cannot load field-projection policy: {error}"
            ) from error
    if policy.get("schema") != EXPECTED_SCHEMA:
        raise ProjectionConfigurationError("Unsupported field-projection schema.")
    resources = policy.get("resources")
    if not isinstance(resources, dict) or not resources:
        raise ProjectionConfigurationError("Projection resources are required.")
    for resource, definition in resources.items():
        if not isinstance(resource, str) or not resource:
            raise ProjectionConfigurationError("Projection resource names are invalid.")
        allowed = definition.get("allowed_fields")
        audiences = definition.get("audiences")
        if (
            not isinstance(allowed, list) or not allowed
            or len(allowed) != len(set(allowed))
            or not all(isinstance(field, str) and field for field in allowed)
        ):
            raise ProjectionConfigurationError(
                f"{resource}: allowed_fields must be unique non-empty strings."
            )
        if not isinstance(audiences, dict) or not audiences:
            raise ProjectionConfigurationError(
                f"{resource}: at least one audience is required."
            )
        for audience, fields in audiences.items():
            if audience not in KNOWN_ROLES | MACHINE_AUDIENCES:
                raise ProjectionConfigurationError(
                    f"{resource}: unknown audience {audience!r}."
                )
            if (
                not isinstance(fields, list)
                or len(fields) != len(set(fields))
                or not set(fields).issubset(allowed)
            ):
                raise ProjectionConfigurationError(
                    f"{resource}/{audience}: fields exceed the allowlist."
                )
    return True


def project_document(
    resource: str, audience: str, document: dict[str, Any]
) -> dict[str, Any]:
    policy = load_projection_policy()
    definition = policy["resources"].get(resource)
    if not definition:
        raise ProjectionConfigurationError(
            f"No governed projection exists for resource {resource!r}."
        )
    fields = definition["audiences"].get(audience)
    if fields is None:
        raise ProjectionConfigurationError(
            f"No {audience!r} projection exists for resource {resource!r}."
        )
    return {field: document[field] for field in fields if field in document}
