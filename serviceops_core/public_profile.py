"""Public profiles: what signed-in colleagues see when they open a person.

"Public" means visible to every active signed-in user of the same
organization -- never outside it. A person's name and role are always shown
(their name already appears on every record they touch); each other field is
shown only while its owner has it switched on. Fields left unset fall back
to the defaults below, so existing users get a sensible profile without
having to visit their settings first.

Administrators see the same public profile as everyone else; the full record
stays on the administration user page.
"""
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import has_request_context
from flask_login import current_user

from serviceops_core.localization import translatable
from serviceops_core.request_cache import request_cache
from serviceops_models import GroupMember, SupportGroup, User, UserPreference, db

# (key, label, public by default)
PROFILE_FIELDS = (
    ("photo", translatable("Profile picture"), True),
    ("title", translatable("Job title"), True),
    ("department", translatable("Department and division"), True),
    ("email", translatable("Email address"), True),
    ("business_phone", translatable("Business phone"), True),
    ("mobile_phone", translatable("Mobile phone"), False),
    ("location", translatable("Location"), True),
    ("local_time", translatable("Local time and timezone"), True),
    ("manager", translatable("Manager"), True),
    ("teams", translatable("Teams"), True),
    ("direct_reports", translatable("Direct reports"), True),
    ("employee_id", translatable("Employee ID"), False),
)
FIELD_KEYS = tuple(key for key, _, _ in PROFILE_FIELDS)
DEFAULTS = {key: default for key, _, default in PROFILE_FIELDS}


def _parse(raw):
    try:
        stored = json.loads(raw or "{}")
    except (TypeError, ValueError):
        stored = {}
    if not isinstance(stored, dict):
        stored = {}
    return {key: stored[key] if isinstance(stored.get(key), bool) else DEFAULTS[key] for key in FIELD_KEYS}


def visibility(user_id):
    """{field: is_public} for one user, cached for the rest of the request."""
    cache = request_cache()
    key = ("profile_visibility", user_id)
    if cache is not None and key in cache:
        return cache[key]
    raw = db.session.query(UserPreference.profile_visibility_json).filter_by(user_id=user_id).scalar()
    result = _parse(raw)
    if cache is not None:
        cache[key] = result
    return result


def prime_visibility(user_ids):
    """Load visibility for many users in one query (comment threads, lists)."""
    cache = request_cache()
    if cache is None:
        return
    missing = [uid for uid in set(user_ids) if uid and ("profile_visibility", uid) not in cache]
    if not missing:
        return
    found = dict(db.session.query(UserPreference.user_id, UserPreference.profile_visibility_json)
                 .filter(UserPreference.user_id.in_(missing)).all())
    for uid in missing:
        cache[("profile_visibility", uid)] = _parse(found.get(uid))


def save_visibility(user, form):
    """Store the switches posted from the profile page (unchecked = private)."""
    preference = UserPreference.query.filter_by(user_id=user.id).first()
    if preference is None:
        preference = UserPreference(user_id=user.id)
        db.session.add(preference)
    chosen = {key: form.get(f"public_{key}") == "on" for key in FIELD_KEYS}
    preference.profile_visibility_json = json.dumps(chosen, sort_keys=True)
    cache = request_cache()
    if cache is not None:
        cache.pop(("profile_visibility", user.id), None)
    return chosen


def photo_visible(user, viewer=None):
    """Whether `viewer` (default: the signed-in user) may see `user`'s picture.
    Owners always see their own; administrators may see it to moderate it."""
    if not user or not user.avatar_path:
        return False
    if viewer is None and has_request_context():
        viewer = current_user
    if viewer is not None and getattr(viewer, "is_authenticated", False):
        if viewer.id == user.id:
            return True
        if viewer.tenant_id != user.tenant_id:
            return False
        import app as core
        if core.role_at_least(viewer.effective_role, "admin"):
            return True
    return visibility(user.id)["photo"]


def can_view_profile(viewer, subject):
    return bool(
        viewer and getattr(viewer, "is_authenticated", False) and viewer.active
        and subject and subject.tenant_id == viewer.tenant_id
    )


def public_profile(subject, viewer):
    """The fields `viewer` may see on `subject`'s profile. The owner gets the
    same projection (it is a preview of what others see) plus the switches."""
    shown = visibility(subject.id)
    profile = {"user": subject, "visibility": shown, "fields": []}

    def add(key, label, value):
        if shown[key] and value:
            profile["fields"].append({"key": key, "label": label, "value": value})

    add("title", translatable("Job title"), subject.title)
    add("department", translatable("Department"), " · ".join(part for part in (subject.department, subject.division) if part))
    add("email", translatable("Email"), subject.email if not subject.email.endswith("@external.serviceops.local") else "")
    add("business_phone", translatable("Business phone"), subject.business_phone)
    add("mobile_phone", translatable("Mobile phone"), subject.mobile_phone)
    add("location", translatable("Location"), subject.location)
    add("employee_id", translatable("Employee ID"), subject.employee_id)
    profile["timezone"] = profile["local_time"] = None
    if shown["local_time"] and subject.timezone:
        try:
            zone = ZoneInfo(subject.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            zone = None
        if zone:
            profile["timezone"] = subject.timezone
            profile["local_time"] = datetime.now(timezone.utc).astimezone(zone).strftime("%H:%M")
    manager = subject.manager
    profile["manager"] = manager if shown["manager"] and manager and manager.tenant_id == subject.tenant_id else None
    profile["teams"] = (
        SupportGroup.query.join(GroupMember, GroupMember.group_id == SupportGroup.id)
        .filter(GroupMember.user_id == subject.id, SupportGroup.active.is_(True),
                SupportGroup.tenant_id == subject.tenant_id)
        .order_by(SupportGroup.name).all()
    ) if shown["teams"] else []
    profile["direct_reports"] = (
        User.query.filter_by(manager_id=subject.id, tenant_id=subject.tenant_id, active=True)
        .order_by(User.name).limit(50).all()
    ) if shown["direct_reports"] else []
    profile["photo"] = photo_visible(subject, viewer)
    return profile
