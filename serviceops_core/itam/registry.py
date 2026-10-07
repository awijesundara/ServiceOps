"""Declarations of the IT asset management record types.

A ResourceType names its model, its fields (how each is edited, validated and
listed), who may change it, and optional hooks: a computed status badge, a
reason it cannot be deleted, and extra validation. The generic pages in
serviceops_core.web.itam do the rest, always scoped to the current tenant.
"""
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Callable

from serviceops_core.localization import tr


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    kind: str = "text"  # text, textarea, email, url, date, int, money, choice, ref, user, cis, bool
    required: bool = False
    choices: tuple = ()
    ref: str = ""  # resource key for kind="ref"
    max_length: int = 160
    in_list: bool = False
    minimum: int = 0
    maximum: int = 100000
    help: str = ""


@dataclass(frozen=True)
class ResourceType:
    key: str
    model_name: str
    label: str
    plural: str
    icon: str
    description: str
    fields: tuple
    title_field: str = "name"
    edit_roles: tuple = ("manager", "admin", "superadmin")
    status: Callable | None = None  # obj -> (label, tone)
    delete_blocker: Callable | None = None  # obj -> reason or None
    validate: Callable | None = None  # (obj, values) -> error or None
    order_by: str = "name"
    search_fields: tuple = ("name",)
    related: tuple = field(default_factory=tuple)  # (title, callable obj -> rows of (label, url, detail))

    @property
    def model(self):
        import serviceops_models
        return getattr(serviceops_models, self.model_name)

    def field(self, name):
        return next(f for f in self.fields if f.name == name)

    def title(self, obj):
        return getattr(obj, self.title_field) or f"#{obj.id}"


RESOURCES = {}


def readable_cis(cis):
    """Use the CMDB policy for linked CI names as well as selection options."""
    from flask_login import current_user
    from serviceops_core.ci_class_policy import unreadable_ci_classes

    denied = unreadable_ci_classes(current_user.tenant_id, current_user.effective_role)
    return [ci for ci in cis if ci.tenant_id == current_user.tenant_id and ci.ci_class not in denied]


def record_id(raw):
    """Bound integer identifiers before converting or passing them to SQL."""
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
        return None
    value = int(raw)
    return value if 0 < value <= 2147483647 else None


def register(resource):
    RESOURCES[resource.key] = resource
    return resource


def parse_value(spec, raw, tenant_id):
    """Convert one submitted form value. Returns (value, error)."""
    from flask import request

    if spec.kind == "bool":
        return bool(raw), None
    if spec.kind == "cis":
        from serviceops_models import ConfigurationItem
        from flask_login import current_user
        from serviceops_core.ci_class_policy import restrict_ci_query_to_readable_classes
        submitted = request.form.getlist(spec.name)
        ids = {record_id(value) for value in submitted}
        if None in ids:
            return None, tr("Choose a valid {label}.", label=tr(spec.label))
        query = restrict_ci_query_to_readable_classes(ConfigurationItem.query.filter(
            ConfigurationItem.tenant_id == tenant_id, ConfigurationItem.id.in_(ids),
        ), tenant_id, current_user.effective_role)
        cis = query.all() if ids else []
        if len(cis) != len(ids):
            return None, tr("Choose a valid {label}.", label=tr(spec.label))
        return cis, None
    raw = (raw or "").strip()
    if not raw:
        if spec.required:
            return None, tr("{label} is required.", label=tr(spec.label))
        if spec.kind == "int":
            return spec.minimum, None
        return ("" if spec.kind in ("text", "textarea", "email", "url", "choice") else None), None
    if spec.kind in ("text", "email", "url", "textarea"):
        limit = spec.max_length if spec.kind != "textarea" else 10000
        if len(raw) > limit:
            return None, tr("{label} must be {limit} characters or fewer.", label=tr(spec.label), limit=limit)
        if spec.kind == "email" and "@" not in raw:
            return None, tr("{label} must be an email address.", label=tr(spec.label))
        if spec.kind == "url" and not raw.lower().startswith(("http://", "https://")):
            return None, tr("{label} must start with http:// or https://.", label=tr(spec.label))
        return raw, None
    if spec.kind == "choice":
        values = [c[0] if isinstance(c, tuple) else c for c in spec.choices]
        return (raw, None) if raw in values else (None, tr("Choose a valid {label}.", label=tr(spec.label)))
    if spec.kind == "date":
        try:
            return date.fromisoformat(raw), None
        except ValueError:
            return None, tr("{label} must be a date (YYYY-MM-DD).", label=tr(spec.label))
    if spec.kind == "int":
        try:
            number = int(raw)
        except ValueError:
            return None, tr("{label} must be a whole number.", label=tr(spec.label))
        if not spec.minimum <= number <= spec.maximum:
            return None, tr("{label} must be between {low} and {high}.", label=tr(spec.label),
                            low=spec.minimum, high=spec.maximum)
        return number, None
    if spec.kind == "money":
        if len(raw) > spec.max_length:
            return None, tr("{label} must be {limit} characters or fewer.", label=tr(spec.label), limit=spec.max_length)
        try:
            amount = Decimal(raw.replace(",", ""))
            if not amount.is_finite():
                return None, tr("{label} must be an amount.", label=tr(spec.label))
            if amount < 0:
                return None, tr("{label} must be between 0 and 999,999,999,999.", label=tr(spec.label))
            amount = amount.quantize(Decimal("0.01"))
            if amount < 0 or amount >= Decimal("1e12"):
                return None, tr("{label} must be between 0 and 999,999,999,999.", label=tr(spec.label))
            return amount, None
        except InvalidOperation:
            return None, tr("{label} must be an amount.", label=tr(spec.label))
    if spec.kind in ("ref", "user"):
        identifier = record_id(raw)
        if identifier is None:
            return None, tr("Choose a valid {label}.", label=tr(spec.label))
        model = RESOURCES[spec.ref].model if spec.kind == "ref" else __import__("serviceops_models").User
        row = model.query.filter_by(id=identifier, tenant_id=tenant_id).first()
        return (row.id, None) if row else (None, tr("Choose a valid {label}.", label=tr(spec.label)))
    return None, tr("Unsupported field.")


def display(spec, obj):
    """A short display string for list cells."""
    value = getattr(obj, spec.name, None)
    if value in (None, ""):
        return "—"
    if spec.kind == "choice":
        for choice in spec.choices:
            if isinstance(choice, tuple) and choice[0] == value:
                return choice[1]
        return value
    if spec.kind == "bool":
        return tr("Yes") if value else tr("No")
    if spec.kind == "money":
        currency = getattr(obj, "currency", "") or ""
        return f"{value:,.2f} {currency}".strip()
    if spec.kind == "ref":
        target = getattr(obj, spec.name.removesuffix("_id"), None)
        return RESOURCES[spec.ref].title(target) if target else "—"
    if spec.kind == "user":
        target = getattr(obj, spec.name.removesuffix("_id"), None)
        return target.name if target else "—"
    if spec.kind == "cis":
        value = readable_cis(value)
        return ", ".join(ci.name for ci in value[:5]) + (" …" if len(value) > 5 else "")
    return str(value)


# ---------------------------------------------------------------- definitions
from serviceops_core.itam import definitions  # noqa: E402,F401 - registers the record types
