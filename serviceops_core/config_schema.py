"""Pure configuration/settings schema and value-coercion logic -- no Flask
or database dependency, matching the bounded-interface pattern already
established by serviceops_core.security. The declarative settings catalog
(what keys exist, their type/default/label) and the string->bool/int
coercion rules live here; the actual database-backed lookup (setting_value())
stays a thin wrapper in app.py since it inherently needs PlatformSetting
and the encryption cipher.
"""
import json


SETTING_DEFINITIONS = {
    "organization": [
        {"key": "INSTANCE_NAME", "label": "Instance name", "type": "text", "default": "ServiceOps", "live": True},
        {"key": "COMPANY_NAME", "label": "Company name", "type": "text", "default": "Your Company", "live": True},
        {"key": "SUPPORT_EMAIL", "label": "Support email", "type": "email", "default": "", "live": True},
    ],
    "appearance": [
        {"key": "BRAND_TEAL", "label": "Primary brand color", "type": "color", "default": "#003e4c", "live": True},
        {"key": "BRAND_AMBER", "label": "Accent brand color", "type": "color", "default": "#f9aa3c", "live": True},
        {"key": "DEFAULT_DENSITY", "label": "Default density", "type": "choice", "choices": ["comfortable", "compact"], "default": "comfortable", "live": True},
    ],
    "sign_in_and_directory": [
        {"key": "LOCAL_AUTH_ENABLED", "label": "Enable local authentication", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_ENABLED", "label": "Enable AD/LDAP", "type": "bool", "default": "false", "live": True},
        {"key": "LDAP_SERVER_URI", "label": "LDAP server URI", "type": "text", "default": "", "live": True},
        {"key": "LDAP_BIND_DN", "label": "LDAP bind DN", "type": "text", "default": "", "live": True},
        {"key": "LDAP_BIND_PASSWORD", "label": "LDAP bind password", "type": "secret", "default": "", "live": True},
        {"key": "LDAP_BASE_DN", "label": "LDAP base DN", "type": "text", "default": "", "live": True},
        {"key": "LDAP_USER_FILTER", "label": "LDAP user filter", "type": "text", "default": "(&(objectClass=user)(sAMAccountName={username}))", "live": True},
        {"key": "LDAP_START_TLS", "label": "Use LDAP StartTLS", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_VALIDATE_CERT", "label": "Validate LDAP certificate", "type": "bool", "default": "true", "live": True},
        {"key": "LDAP_ROLE_MAPPINGS", "label": "LDAP group role mappings", "type": "json", "default": "{}", "live": True},
        {
            "key": "LDAP_ATTR_MAP", "label": "LDAP directory attribute map", "type": "json",
            "default": json.dumps({
                "title": "title", "department": "department", "division": "division",
                "employee_id": "employeeID", "employee_type": "employeeType", "manager": "manager",
                "email": "mail", "display_name": "displayName", "username": "sAMAccountName",
                "business_phone": "telephoneNumber", "mobile_phone": "mobile",
                "location": "physicalDeliveryOfficeName",
            }),
            "live": True,
        },
        {
            "key": "KEYCLOAK_ATTR_MAP", "label": "Keycloak/OIDC directory attribute map", "type": "json",
            "default": json.dumps({
                "title": "title", "department": "department", "division": "division",
                "employee_id": "employee_id", "employee_type": "employee_type",
                "business_phone": "phone_number", "mobile_phone": "mobile_number",
                "location": "location",
            }),
            "live": True,
        },
        {"key": "LDAP_SYNC_ENABLED", "label": "Enable scheduled LDAP directory sync", "type": "bool", "default": "false", "live": True},
        {"key": "LDAP_SYNC_INTERVAL_MINUTES", "label": "LDAP directory sync interval (minutes)", "type": "int", "default": "60", "min": 5, "max": 10080, "live": True},
        {"key": "KEYCLOAK_ENABLED", "label": "Enable Keycloak", "type": "bool", "default": "false", "live": False},
        {"key": "KEYCLOAK_DISCOVERY_URL", "label": "Keycloak discovery URL", "type": "url", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_ID", "label": "Keycloak client ID", "type": "text", "default": "", "live": False},
        {"key": "KEYCLOAK_CLIENT_SECRET", "label": "Keycloak client secret", "type": "secret", "default": "", "live": False},
        {"key": "KEYCLOAK_ROLE_MAPPINGS", "label": "Keycloak realm-role mappings", "type": "json", "default": "{}", "live": True},
    ],
    "security": [
        {"key": "ENABLE_HSTS", "label": "Enable HSTS", "type": "bool", "default": "false", "live": True},
        {"key": "SESSION_HOURS", "label": "Session lifetime in hours", "type": "int", "default": "8", "min": 1, "max": 168, "live": False},
        {"key": "PASSWORD_MIN_LENGTH", "label": "Minimum local password length", "type": "int", "default": "14", "min": 8, "max": 64, "live": True},
        {"key": "MAX_UPLOAD_MB", "label": "Maximum upload size (MB)", "type": "int", "default": "20", "min": 1, "max": 500, "live": True},
        {"key": "AUDIT_STREAM_ENABLED", "label": "Stream audit events to SIEM", "type": "bool", "default": "false", "live": True},
        {"key": "LOGIN_MAX_ATTEMPTS", "label": "Failed logins before lockout", "type": "int", "default": "5", "min": 3, "max": 20, "live": True},
        {"key": "LOGIN_LOCKOUT_MINUTES", "label": "Lockout duration in minutes", "type": "int", "default": "15", "min": 1, "max": 1440, "live": True},
        {"key": "API_RATE_LIMIT_PER_MINUTE", "label": "REST API requests per minute (per client)", "type": "int", "default": "120", "min": 10, "max": 6000, "live": True},
        {"key": "LOGIN_RATE_LIMIT_PER_IP_PER_MINUTE", "label": "Login attempts per minute (per source IP)", "type": "int", "default": "20", "min": 5, "max": 1000, "live": True},
        {"key": "LOGIN_RATE_LIMIT_PER_ACCOUNT_PER_MINUTE", "label": "Login attempts per minute (per account)", "type": "int", "default": "10", "min": 3, "max": 1000, "live": True},
        {"key": "REQUIRE_MFA_FOR_ADMIN", "label": "Require MFA for admin and CCB accounts", "type": "bool", "default": "false", "live": True},
        {"key": "CLAMAV_ENABLED", "label": "Scan attachments with ClamAV", "type": "bool", "default": "false", "live": True},
        {"key": "CLAMAV_HOST", "label": "ClamAV daemon host", "type": "text", "default": "", "live": True},
        {"key": "CLAMAV_PORT", "label": "ClamAV daemon port", "type": "int", "default": "3310", "min": 1, "max": 65535, "live": True},
    ],
    "workspace_defaults": [
        {"key": "DASHBOARD_SHOW_MY_ASSIGNED", "label": "Show \"Assigned to me\"", "type": "bool", "default": "true", "live": True},
        {"key": "DASHBOARD_SHOW_SLA_WIDGETS", "label": "Show SLA breached / at-risk widgets", "type": "bool", "default": "true", "live": True},
        {"key": "DASHBOARD_SHOW_RECENT", "label": "Show \"Recently updated\"", "type": "bool", "default": "true", "live": True},
        {"key": "SLA_AT_RISK_HOURS", "label": "SLA \"at risk\" warning window (hours)", "type": "int", "default": "4", "min": 1, "max": 72, "live": True},
    ],
    "my_workspace_widgets": [
        # One bool per WORKSPACE_WIDGET_REGISTRY entry (B-121 governance):
        # an admin can disable a widget tenant-wide, which drops it from
        # both the picker and any layout that already included it (skipped
        # at render time, not an error) without deleting anyone's saved
        # layout. Kept as a hand-written list (not generated from the
        # registry at import time) to match this file's existing
        # convention of a static, readable settings schema.
        {"key": "WORKSPACE_WIDGET_TICKET_STATS_ENABLED", "label": "Ticket counts", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_MY_OPEN_TICKETS_ENABLED", "label": "My open tickets", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_RECENT_TICKETS_ENABLED", "label": "Recently updated tickets", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_SLA_AT_RISK_ENABLED", "label": "SLA at risk", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_APPROVALS_AWAITING_ME_ENABLED", "label": "Approvals awaiting me", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_FAVORITES_ENABLED", "label": "Favorites", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_RECENTLY_VIEWED_ENABLED", "label": "Recently viewed", "type": "bool", "default": "true", "live": True},
        {"key": "WORKSPACE_WIDGET_NOTIFICATIONS_ENABLED", "label": "Notifications", "type": "bool", "default": "true", "live": True},
    ],
    "email_delivery": [
        {"key": "SMTP_ENABLED", "label": "Enable SMTP delivery", "type": "bool", "default": "false", "live": True},
        {"key": "SMTP_HOST", "label": "SMTP host", "type": "text", "default": "", "live": True},
        {"key": "SMTP_PORT", "label": "SMTP port", "type": "int", "default": "587", "min": 1, "max": 65535, "live": True},
        {"key": "SMTP_STARTTLS", "label": "Require SMTP STARTTLS", "type": "bool", "default": "true", "live": True},
        {"key": "SMTP_USERNAME", "label": "SMTP username", "type": "text", "default": "", "live": True},
        {"key": "SMTP_PASSWORD", "label": "SMTP password", "type": "secret", "default": "", "live": True},
        {"key": "SMTP_FROM", "label": "SMTP from address", "type": "email", "default": "", "live": True},
    ],
    "netbox_connection": [
        {"key": "NETBOX_ENABLED", "label": "Enable NetBox sync", "type": "bool", "default": "false", "live": True},
        {"key": "NETBOX_BASE_URL", "label": "NetBox base URL", "type": "url", "default": "", "live": True},
        {"key": "NETBOX_API_TOKEN", "label": "NetBox API token", "type": "secret", "default": "", "live": True},
        {
            "key": "NETBOX_CA_CERT", "type": "text", "default": "", "live": True,
            "label": "NetBox CA certificate (PEM, only needed if NetBox uses an internal CA)",
        },
        {
            "key": "NETBOX_TLS_INSECURE", "type": "bool", "default": "false", "live": True,
            "label": "Skip NetBox TLS certificate verification (insecure — last resort, prefer the CA certificate above)",
        },
    ],
    "request_tracker_connection": [
        {"key": "RT_ENABLED", "label": "Enable Request Tracker (RT) import", "type": "bool", "default": "false", "live": True},
        {"key": "RT_BASE_URL", "label": "RT base URL", "type": "url", "default": "", "live": True},
        {"key": "RT_API_TOKEN", "label": "RT API token", "type": "secret", "default": "", "live": True},
        {
            "key": "RT_CA_CERT", "type": "text", "default": "", "live": True,
            "label": "RT CA certificate (PEM, only needed if RT uses an internal CA)",
        },
        {
            "key": "RT_TLS_INSECURE", "type": "bool", "default": "false", "live": True,
            "label": "Skip RT TLS certificate verification (insecure — last resort, prefer the CA certificate above)",
        },
    ],
}


SETTING_GROUP_META = {
    "organization": ("Organization", "Company identity, support contact, and instance-wide naming."),
    "appearance": ("Appearance", "Brand colors and the default screen density for new users."),
    "sign_in_and_directory": ("Sign-in and directory", "Local login, AD/LDAP, Keycloak, directory attributes, and synchronization."),
    "security": ("Security and limits", "Sessions, passwords, MFA, rate limits, uploads, malware scanning, and audit streaming."),
    "workspace_defaults": ("Workspace defaults", "Dashboard content and service-level warning thresholds."),
    "my_workspace_widgets": ("My Workspace widgets", "Which widgets are available for users to add to their personal My Workspace page."),
    "email_delivery": ("Email delivery", "SMTP connection and sender identity used for outgoing notifications."),
    "netbox_connection": ("NetBox connection", "Connection used to synchronize configuration items from NetBox."),
    "request_tracker_connection": ("Request Tracker connection", "Connection used to import records from Request Tracker."),
}


def find_setting_definition(key):
    """The definition dict for a given setting key, across every group, or
    None if it isn't a known key (e.g. a stale PlatformSetting row from a
    removed setting)."""
    return next(
        (item for group in SETTING_DEFINITIONS.values() for item in group if item["key"] == key),
        None,
    )


def coerce_bool(value):
    return str(value).lower() in {"1", "true", "yes", "on"}


def coerce_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
