"""External identity: SSO/LDAP account provisioning, the LDAP login bind,
and Cloudflare Access JWT verification.

Moved from app.py; app.py re-exports every public name here, so existing
callers (`from app import provision_external_user`, `core_app.ldap_authenticate`)
are unchanged. Helpers that still live in app.py -- and names tests patch on
the app module (`Connection`, `now`, `setting_value`,
`ldap_server_and_service_connection`) -- are looked up through `core_app` at
call time so those patches keep taking effect.
"""
import json
import os
import ssl
import threading
import time as time_module
import uuid

import requests
from cryptography.fernet import InvalidToken
from flask import current_app
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from ldap3 import ALL, BASE, FIRST, SUBTREE, Server, ServerPool, Tls
from ldap3.utils.conv import escape_filter_chars

from serviceops_core.identity import (
    ldap_domain_suffix_from_base_dn, ldap_login_local_part, normalize_email,
)
from serviceops_core.security import hash_password
from serviceops_models import (
    DirectoryProfile, ExternalIdentity, PlatformSetting, ROLE_RANK, User, db, settings_cipher,
)


class _CoreApp:
    """Resolves app-module attributes at call time. Importing app at module
    level would be circular (app.py imports this module part-way through its
    own initialization), so this defers it the same way other
    serviceops_core modules do with a function-level `import app`."""

    def __getattr__(self, name):
        import app
        return getattr(app, name)


core_app = _CoreApp()


def apply_external_profile_attrs(user, profile_attrs):
    """Copy directory/SSO-sourced profile fields (title, department, employee
    id, phone, mobile, location, ...) onto ``user``, never nulling out an
    existing value for an attribute the provider didn't send this time
    (sparse claim sets are normal for OIDC userinfo)."""
    if not profile_attrs:
        return
    from serviceops_core.ldap_sync import PROFILE_FIELDS
    for field in PROFILE_FIELDS:
        value = profile_attrs.get(field)
        if value:
            setattr(user, field, str(value).strip())


def apply_directory_profile(user, profile, group_names=None):
    """Persist only the normalized LDAP snapshot produced by ldap_sync.

    This is intentionally separate from User columns: it gives self-service
    and administrators richer directory context without letting opaque AD
    blobs leak into the database or become authorization inputs.
    """
    if not user or not isinstance(profile, dict):
        return None
    row = DirectoryProfile.query.filter_by(user_id=user.id).first()
    if not row:
        row = DirectoryProfile(user_id=user.id, tenant_id=user.tenant_id)
        db.session.add(row)
    row.profile_json = json.dumps(profile, sort_keys=True)
    row.groups_json = json.dumps(sorted(set(group_names or []), key=str.casefold))
    row.synchronized_at = core_app.now()
    return row


def find_external_identity(provider, subject):
    """Return an existing external identity using provider-correct equality.

    LDAP distinguished names are not stable byte strings: equivalent DNs can
    be returned with different character casing (including between the user's
    login search and the manager base-object lookup).  Treating them as exact,
    case-sensitive subjects can create a second placeholder user and make a
    reporting relationship appear to flap.  Other identity providers keep
    exact subject matching because their subject identifiers are opaque.
    """
    provider = str(provider or "").strip()
    subject = str(subject or "").strip()
    if not provider or not subject:
        return None
    query = ExternalIdentity.query.filter_by(provider=provider)
    if provider.casefold() == "ldap":
        return query.filter(
            db.func.lower(db.func.trim(ExternalIdentity.subject)) == subject.casefold()
        ).first()
    return query.filter_by(subject=subject).first()


class ExternalIdentityLinkRefused(RuntimeError):
    """An SSO login matched an existing account it is not trusted to claim.

    Raised instead of linking (which would hand over that account) or
    provisioning a second, disconnected account under the same person."""


def email_taken_by_other(email, user_id=None):
    """True when another account already holds this address in any letter
    case. Login paths match emails case-insensitively, so a case variant is
    as much a collision as an exact duplicate."""
    query = User.query.filter(db.func.lower(User.email) == (email or "").strip().lower())
    if user_id is not None:
        query = query.filter(User.id != user_id)
    return db.session.query(query.exists()).scalar()


def provision_external_user(
    provider, subject, username, name, email, matched_roles, groups=None,
    profile_attrs=None, directory_profile=None, directory_group_names=None,
    email_verified=None,
):
    """`matched_roles` is normally a {role: matched_group_or_None} dict from
    mapped_roles() -- every one of these roles is granted via
    sync_role_grants(..., source="directory"), and any previously
    directory-granted role no longer matched is revoked, without ever
    touching a manually-granted or team-responsibility-granted role. A bare
    role string or an iterable of role strings is also accepted for
    callers that only have a single/plain set of roles.

    ``profile_attrs``, when given, is a {User-column-name: value} dict of
    directory/SSO profile fields (see PROFILE_FIELDS in ldap_sync.py) applied
    to the user record on every login -- e.g. Keycloak/OIDC's department,
    employee ID, phone, mobile, location claims (KEYCLOAK_ATTR_MAP setting).

    ``email_verified`` is the identity provider's own assertion that the
    person controls ``email`` (the OIDC ``email_verified`` claim). The LDAP
    directory is administrator-controlled and treated as verified; for every
    other provider an unverified address is never used to adopt an existing
    account or overwrite a stored one, and the username fallback is LDAP-only
    -- an OIDC ``preferred_username`` is frequently user-chosen, so matching
    on it would let anyone who registers as "admin" claim that account.
    """
    trusted_email = provider == "ldap" or email_verified is True
    if isinstance(matched_roles, str):
        matched_roles = {matched_roles: None}
    elif not isinstance(matched_roles, dict):
        matched_roles = {role: None for role in matched_roles}

    identity = find_external_identity(provider, subject)
    if identity:
        user = identity.user
        user.name = name
        new_email = normalize_email(email)
        if trusted_email and new_email and not email_taken_by_other(new_email, user.id):
            user.email = new_email
        # Deliberately does NOT force user.active = True here: an
        # administrator deactivating a directory-linked account is an
        # explicit access decision (the platform manual promises
        # "re-enablement remains an explicit administrative decision"),
        # and a successful directory bind must not silently override it.
        # A brand-new account (below) still defaults active via the User
        # model's own column default.
        apply_external_profile_attrs(user, profile_attrs)
        if provider == "ldap" and directory_profile is not None:
            apply_directory_profile(user, directory_profile, directory_group_names)
        core_app.sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            core_app.sync_directory_team_memberships(
                user, groups, declared_team=(profile_attrs or {}).get("team_name")
            )
            core_app.sync_implied_role_grants(user)
        return user

    base = (username or f"{provider}-{uuid.uuid4().hex[:8]}").strip().lower()[:70]
    email_lower = (email or "").strip().lower()

    # A user account that already exists under this username or email --
    # e.g. a placeholder auto-created by RT import (serviceops_core/rt_import.py)
    # matching an RT Requestor/Owner by email, or any other manually-created
    # local account -- must be adopted into this identity on first login
    # rather than getting a second, disconnected account with a suffixed
    # username. Without this, an RT-imported person's real LDAP login never
    # picks up their group memberships/team assignments (sync_directory_team_memberships
    # never runs against their real account), and they end up with two
    # unrelated users: the orphaned RT one holding all their imported
    # tickets, and a fresh empty one they actually log into.
    existing_user = None
    if email_lower:
        existing_user = User.query.filter(db.func.lower(User.email) == email_lower).first()
        if existing_user and not trusted_email:
            raise ExternalIdentityLinkRefused(
                f"provider={provider}; reason=unverified_email_matches_existing_account"
            )
    if not existing_user and base and provider == "ldap":
        existing_user = User.query.filter_by(username=base).first()
    if existing_user and not ExternalIdentity.query.filter_by(
        provider=provider, user_id=existing_user.id
    ).first():
        existing_user.name = name or existing_user.name
        existing_user.email = normalize_email(email) or existing_user.email
        # Same reasoning as the returning-identity branch above: don't
        # override an administrator's explicit deactivation just because
        # this local account is being linked to a directory identity.
        apply_external_profile_attrs(existing_user, profile_attrs)
        if provider == "ldap" and directory_profile is not None:
            apply_directory_profile(existing_user, directory_profile, directory_group_names)
        db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=existing_user.id))
        core_app.sync_role_grants(existing_user, "directory", matched_roles, detail_by_role=matched_roles)
        if provider == "ldap":
            core_app.sync_directory_team_memberships(
                existing_user, groups, declared_team=(profile_attrs or {}).get("team_name")
            )
            core_app.sync_implied_role_grants(existing_user)
        return existing_user

    candidate, suffix = base, 1
    while User.query.filter_by(username=candidate).first():
        suffix += 1
        candidate = f"{base[:70]}-{suffix}"
    # An unverified address is not recorded: the Cloudflare Access shortcut
    # signs people in by stored email, so keeping it would let whoever
    # registered it first receive the real owner's later logins.
    unique_email = (
        (normalize_email(email) if trusted_email else None)
        or f"{candidate}@external.serviceops.local"
    )
    if email_taken_by_other(unique_email):
        unique_email = f"{provider}-{uuid.uuid4().hex[:8]}@external.serviceops.local"
    initial_role = (
        max(matched_roles, key=lambda r: ROLE_RANK.get(r, -1)) if matched_roles else "requester"
    )
    user = User(username=candidate, name=name or candidate, email=unique_email,
                password_hash=hash_password(uuid.uuid4().hex), role=initial_role)
    db.session.add(user)
    db.session.flush()
    apply_external_profile_attrs(user, profile_attrs)
    if provider == "ldap" and directory_profile is not None:
        apply_directory_profile(user, directory_profile, directory_group_names)
    db.session.add(ExternalIdentity(provider=provider, subject=subject, user_id=user.id))
    core_app.sync_role_grants(user, "directory", matched_roles, detail_by_role=matched_roles)
    if provider == "ldap":
        core_app.sync_directory_team_memberships(
            user, groups, declared_team=(profile_attrs or {}).get("team_name")
        )
        core_app.sync_implied_role_grants(user)
    return user


class LdapBindError(RuntimeError):
    """Raised when a service-account LDAP bind cannot be established."""


def ldap_server_and_service_connection():
    """Build the ldap3 Server plus a bound service-account Connection, shared by
    interactive login (ldap_authenticate) and the directory sync job. Raises
    LdapBindError rather than returning a half-usable connection so callers
    never mistake a failed bind for "no directory configured"."""
    from serviceops_core.ldap_access import server_uris
    uris = server_uris(core_app.setting_value("LDAP_SERVER_URI", ""))
    if not uris:
        raise LdapBindError("LDAP_SERVER_URI is not configured.")
    use_ssl = uris[0].lower().startswith("ldaps://")
    if any(uri.lower().startswith("ldaps://") != use_ssl for uri in uris):
        raise LdapBindError("Every LDAP server URI must use the same scheme (ldap:// or ldaps://).")
    validate = ssl.CERT_REQUIRED if core_app.setting_bool("LDAP_VALIDATE_CERT", True) else ssl.CERT_NONE
    tls = Tls(validate=validate, ca_certs_file=os.getenv("LDAP_CA_CERT") or None)
    servers = []
    for uri in uris:
        address = uri.split("://", 1)[-1].split("/", 1)[0]
        host, _, explicit_port = address.partition(":")
        port = int(explicit_port or os.getenv("LDAP_PORT", "636" if use_ssl else "389"))
        servers.append(Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL,
                              connect_timeout=int(os.getenv("LDAP_TIMEOUT", "8"))))
    # Several servers fail over in the order listed; a server that does not
    # answer is skipped until it recovers.
    server = servers[0] if len(servers) == 1 else ServerPool(servers, FIRST, active=1, exhaust=60)
    bind_dn = core_app.setting_value("LDAP_BIND_DN") or None
    bind_password = None
    if bind_dn:
        # Resolve the bind password directly rather than through setting_value(),
        # which silently falls back to "" (anonymous bind) if decryption fails —
        # a key-rotation or config mistake must not silently degrade a configured
        # authenticated bind into an anonymous one.
        password_row = db.session.get(PlatformSetting, "LDAP_BIND_PASSWORD")
        if password_row and password_row.encrypted:
            try:
                bind_password = settings_cipher().decrypt(password_row.value.encode()).decode() or None
            except (InvalidToken, ValueError):
                current_app.logger.error(
                    "LDAP bind password could not be decrypted; refusing to fall back "
                    "to an anonymous bind for a configured bind DN."
                )
                raise LdapBindError("LDAP bind password could not be decrypted.")
        elif password_row:
            bind_password = password_row.value or None
    service = core_app.Connection(server, user=bind_dn, password=bind_password,
                         auto_bind=False, receive_timeout=int(os.getenv("LDAP_TIMEOUT", "8")))
    service.open()
    if not use_ssl and core_app.setting_bool("LDAP_START_TLS", True):
        if not service.start_tls():
            raise LdapBindError("LDAP StartTLS negotiation failed.")
    if not service.bind():
        raise LdapBindError("LDAP service-account bind failed.")
    return server, service


def sync_ldap_manager_on_login(user, entry_dn, manager_dn, merged_attr_map):
    """Best-effort manager mapping for LDAP login.

    Runs on successful login so org-chart links stay current without relying
    on periodic/full-directory sync. Never raises -- login must continue even
    if manager lookup fails.
    """
    if not user or not entry_dn or not manager_dn:
        return
    entry_key = str(entry_dn).strip().casefold()
    manager_key = str(manager_dn).strip().casefold()
    if not entry_key or not manager_key:
        return
    if entry_key == manager_key:
        current_app.logger.warning(
            "Self-manager LDAP record skipped for user %s.",
            user.username,
        )
        return

    try:
        previous_manager = db.session.get(User, user.manager_id) if user.manager_id else None
        manager_identity = find_external_identity("ldap", manager_dn)
        manager_user = manager_identity.user if manager_identity else None

        if not manager_user:
            _server, service = core_app.ldap_server_and_service_connection()
            try:
                if not service.search(
                    search_base=manager_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=sorted(set(merged_attr_map.values()) | {
                        merged_attr_map.get("username", "sAMAccountName"),
                        merged_attr_map.get("display_name", "displayName"),
                        merged_attr_map.get("email", "mail"),
                        "memberOf",
                    }),
                    size_limit=1,
                ):
                    return
                entries = list(service.entries)
            finally:
                try:
                    service.unbind()
                except Exception:
                    pass
            if not entries:
                return
            values = entries[0].entry_attributes_as_dict
            first = lambda key, fallback="": (values.get(key) or [fallback])[0]
            manager_username = first(merged_attr_map.get("username", "sAMAccountName"), "")
            if not manager_username:
                return
            manager_groups = values.get("memberOf", [])
            manager_roles = core_app.mapped_roles(manager_groups, "LDAP_ROLE_MAPPINGS")
            manager_profile_attrs = {}
            from serviceops_core.ldap_sync import (
                PROFILE_FIELDS, directory_profile_payload,
            )
            for field in PROFILE_FIELDS:
                ldap_attr = merged_attr_map.get(field)
                if not ldap_attr:
                    continue
                val = first(ldap_attr, "")
                if val:
                    manager_profile_attrs[field] = val
            manager_directory_profile, manager_group_names = directory_profile_payload(
                values, manager_groups, merged_attr_map, manager_dn
            )
            manager_profile_attrs["team_name"] = manager_directory_profile.get("team_name")
            manager_user = provision_external_user(
                "ldap",
                manager_dn,
                manager_username,
                first(merged_attr_map.get("display_name", "displayName"), manager_username),
                first(merged_attr_map.get("email", "mail"), ""),
                manager_roles,
                groups=manager_groups,
                profile_attrs=manager_profile_attrs,
                directory_profile=manager_directory_profile,
                directory_group_names=manager_group_names,
            )

        if manager_user and manager_user.id != user.id and manager_user.tenant_id == user.tenant_id:
            if user.manager_id != manager_user.id:
                user.manager_id = manager_user.id
            core_app.sync_implied_role_grants(manager_user)
            core_app.reconcile_directory_team_managers(user)
            if previous_manager and previous_manager.id != manager_user.id:
                core_app.sync_implied_role_grants(previous_manager)
    except Exception as error:  # noqa: BLE001 - login must not fail on manager sync
        current_app.logger.warning(
            "LDAP manager sync on login failed for %s: %s",
            user.username,
            type(error).__name__,
        )


def ldap_username_placeholder():
    """Ghost text for the login form's username field. Thin DB-backed
    wrapper: fetches LDAP_ENABLED/LDAP_BASE_DN, delegates the actual
    domain-derivation to serviceops_core.identity.ldap_domain_suffix_from_base_dn()."""
    if not core_app.setting_bool("LDAP_ENABLED"):
        return "Username"
    domain = ldap_domain_suffix_from_base_dn(core_app.setting_value("LDAP_BASE_DN", ""))
    return f"jsmith or jsmith@{domain}" if domain else "jsmith"


_cloudflare_access_jwks_cache = {"fetched_at": 0.0, "key_set": None}
_cloudflare_access_jwks_lock = threading.Lock()


def _cloudflare_access_key_set():
    """Fetches (and caches for 1 hour, per worker process) Cloudflare
    Access's RS256 public keys for this team as a joserfc KeySet.

    Guarded by a lock so that several request-handling threads (gunicorn's
    gthread worker class) racing in at the moment the cache expires don't
    each independently fire a redundant fetch against Cloudflare -- the
    lock is held only around the check-refresh, never across a verified
    JWT's own signature check."""
    with _cloudflare_access_jwks_lock:
        if time_module.monotonic() - _cloudflare_access_jwks_cache["fetched_at"] < 3600 and _cloudflare_access_jwks_cache["key_set"] is not None:
            return _cloudflare_access_jwks_cache["key_set"]
        team_domain = current_app.config["CLOUDFLARE_ACCESS_TEAM_DOMAIN"]
        response = requests.get(f"https://{team_domain}/cdn-cgi/access/certs", timeout=5,
                                proxies=core_app.resolve_component_proxies("CLOUDFLARE_ACCESS"))
        response.raise_for_status()
        key_set = KeySet.import_key_set(response.json())
        _cloudflare_access_jwks_cache["key_set"] = key_set
        _cloudflare_access_jwks_cache["fetched_at"] = time_module.monotonic()
        return key_set


def verify_cloudflare_access_jwt(token):
    """Verifies a Cloudflare Access-issued JWT (the Cf-Access-Jwt-Assertion
    header Access forwards to the origin once a request has passed the edge)
    against this team's public keys: signature, audience, and expiry.
    Returns the verified claims dict on success, None on any failure --
    never raises, since a missing/invalid header must fall back to the
    existing local/LDAP/Keycloak login form, not error out."""
    team_domain = current_app.config["CLOUDFLARE_ACCESS_TEAM_DOMAIN"]
    aud = current_app.config["CLOUDFLARE_ACCESS_AUD"]
    if not team_domain or not aud or not token:
        return None
    try:
        key_set = _cloudflare_access_key_set()
        decoded = jwt.decode(token, key_set, algorithms=["RS256"])
        claims_registry = JWTClaimsRegistry(
            aud={"essential": True, "value": aud},
            iss={"essential": True, "value": f"https://{team_domain}"},
        )
        claims_registry.validate(decoded.claims)
        return decoded.claims
    except Exception:
        current_app.logger.info("Cloudflare Access JWT verification failed", exc_info=True)
        return None


def ldap_authenticate(username, password):
    if not password or not core_app.setting_bool("LDAP_ENABLED"):
        return None
    try:
        server, service = core_app.ldap_server_and_service_connection()
    except LdapBindError:
        return None
    use_ssl = core_app.setting_value("LDAP_SERVER_URI", "").strip().lower().startswith("ldaps://")
    filter_template = core_app.setting_value(
        "LDAP_USER_FILTER", "(&(objectClass=user)(sAMAccountName={username}))"
    )
    base_dn = core_app.setting_value("LDAP_BASE_DN", "")
    try:
        ldap_attr_map = json.loads(core_app.setting_value("LDAP_ATTR_MAP", "{}"))
    except (TypeError, json.JSONDecodeError):
        ldap_attr_map = {}
    from serviceops_core.ldap_sync import (
        DEFAULT_ATTR_MAP, PROFILE_FIELDS, directory_profile_payload,
    )
    attr_names = {
        "distinguishedName", "cn", "displayName", "mail", "memberOf", "userPrincipalName"
    }
    attr_names.update(DEFAULT_ATTR_MAP.values())
    for mapped in ldap_attr_map.values() if isinstance(ldap_attr_map, dict) else []:
        if isinstance(mapped, str) and mapped.strip():
            attr_names.add(mapped.strip())
    attrs = sorted(attr_names)
    # Try the bare local part first (e.g. "jsmith" from either "jsmith",
    # "jsmith@company.com", or "CORP\jsmith") since sAMAccountName -- what
    # the default filter and most deployments match against -- only ever
    # holds that bare form. If a site has customized LDAP_USER_FILTER to
    # match userPrincipalName instead, the bare local part alone won't
    # match a full UPN there, so fall back to the exact string the user
    # typed. This fixes every existing deployment (default or
    # sAMAccountName-based custom filters) immediately, with no settings
    # change required, while staying backward-compatible with filters that
    # deliberately expect a full UPN.
    local_part = ldap_login_local_part(username)
    candidates = [local_part] if local_part == username else [local_part, username]
    entries = []
    for candidate in candidates:
        search_filter = filter_template.replace("{username}", escape_filter_chars(candidate))
        if service.search(base_dn, search_filter, search_scope=SUBTREE, attributes=attrs, size_limit=2):
            entries = list(service.entries)
            if len(entries) == 1:
                break
    if len(entries) != 1:
        service.unbind()
        return None
    entry = entries[0]
    from serviceops_core.ldap_access import resolve_groups, sign_in_allowed
    try:
        groups = resolve_groups(
            service, entry.entry_dn, ldap_login_local_part(username),
            entry.entry_attributes_as_dict.get("memberOf", []),
        )
    finally:
        service.unbind()
    user_conn = core_app.Connection(server, user=entry.entry_dn, password=password, auto_bind=False)
    user_conn.open()
    # Every early return below must unbind first -- only the success path
    # used to, leaking one open socket per failed login attempt (wrong
    # password, or a server that always rejects StartTLS) until GC/timeout
    # reclaimed it.
    if not use_ssl and core_app.setting_bool("LDAP_START_TLS", True) and not user_conn.start_tls():
        user_conn.unbind()
        return None
    if not user_conn.bind():
        user_conn.unbind()
        return None
    user_conn.unbind()
    values = entry.entry_attributes_as_dict
    first = lambda key, fallback="": (values.get(key) or [fallback])[0]
    if not sign_in_allowed(groups):
        # Checked only after the password bind succeeds, so the refusal never
        # reveals whether an account exists or is merely outside the mapped groups.
        # The caller records the failed sign-in in the audit log.
        current_app.logger.info("LDAP sign-in refused: user is not in a mapped access group.")
        return None
    matched_roles = core_app.mapped_roles(groups, "LDAP_ROLE_MAPPINGS")
    merged_attr_map = dict(DEFAULT_ATTR_MAP)
    if isinstance(ldap_attr_map, dict):
        merged_attr_map.update({k: v for k, v in ldap_attr_map.items() if isinstance(v, str) and v})
    profile_attrs = {}
    for field in PROFILE_FIELDS:
        ldap_attr = merged_attr_map.get(field)
        if not ldap_attr:
            continue
        val = first(ldap_attr, "")
        if val:
            profile_attrs[field] = val
    directory_profile, directory_group_names = directory_profile_payload(
        values, groups, merged_attr_map, entry.entry_dn
    )
    profile_attrs["team_name"] = directory_profile.get("team_name")
    # Use the bare local part, not whatever form the user happened to type
    # this time, as the new account's username -- entry.entry_dn is the
    # actual matching key for returning logins (see
    # provision_external_user's ExternalIdentity lookup), so this only
    # affects the username assigned the very first time this person logs
    # in, but "jsmith@company.com" as a permanent account name would be an
    # ugly, confusing artifact of whichever login form they happened to
    # type first.
    user = provision_external_user(
        "ldap", entry.entry_dn, local_part, first("displayName", first("cn", local_part)),
        first("mail", first("userPrincipalName", "")), matched_roles, groups=groups,
        profile_attrs=profile_attrs,
        directory_profile=directory_profile,
        directory_group_names=directory_group_names,
    )
    manager_dn = first(merged_attr_map.get("manager", "manager"), "")
    sync_ldap_manager_on_login(user, entry.entry_dn, manager_dn, merged_attr_map)
    return user
