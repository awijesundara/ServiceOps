"""Pure navigation-search catalogue for the ServiceOps shell.

Keeping this declarative catalogue outside ``app.py`` avoids rebuilding a
large mutable list on every search request and gives navigation discoverability
one independently testable source of truth.
"""

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True, slots=True)
class NavigationEntry:
    label: str
    keywords: str
    endpoint: str
    params: Mapping[str, str] = field(default_factory=dict)
    minimum_role: str | None = None
    client_management: bool = False


NAVIGATION_ENTRIES = (
    NavigationEntry("Dashboard", "Service operations home overview", "dashboard"),
    NavigationEntry("Visual task board", "Tasks and operational work board", "task_board"),
    NavigationEntry("My tasks", "Work assigned to me", "my_work_tasks", minimum_role="agent"),
    NavigationEntry("Incidents", "Incident Management open active critical", "tickets", {"kind": "incident"}),
    NavigationEntry("Service requests", "Request Fulfilment requested items", "requests_list"),
    NavigationEntry("Changes", "Change Management calendar approvals", "tickets", {"kind": "change"}, "agent"),
    NavigationEntry("Service catalog", "Catalog items request services", "catalog"),
    NavigationEntry("Knowledge", "Knowledge Management articles search", "knowledge"),
    NavigationEntry("All workspaces", "Installed enterprise applications modules", "modules"),
    NavigationEntry("My approvals", "Pending approvals", "approval_chains"),
    NavigationEntry("Notifications", "Alerts messages", "notifications"),
    NavigationEntry("Organization chart", "People reporting structure", "org_chart"),
    NavigationEntry("Manager portal", "Leadership teams workload", "manager_portal", minimum_role="manager"),
    NavigationEntry("Problems", "Problem Management root cause", "module_records", {"domain": "problem"}, "agent"),
    NavigationEntry("Known errors", "Workarounds Problem Management", "known_errors", minimum_role="agent"),
    NavigationEntry("IT operations", "Events infrastructure operations", "module_records", {"domain": "event"}, "agent"),
    NavigationEntry("Improvements", "Continual improvement", "improvements", minimum_role="agent"),
    NavigationEntry("CMDB and service map", "Configuration Management Database CI relationships", "cmdb", minimum_role="agent"),
    NavigationEntry("Assets", "Asset Management inventory", "assets", minimum_role="agent"),
    NavigationEntry("Analytics", "Reports dashboards service performance", "analytics", minimum_role="agent"),
    NavigationEntry("Administration home", "Platform administration configuration", "admin_home", minimum_role="admin"),
    NavigationEntry("Platform settings", "Security authentication email infrastructure", "system_settings", minimum_role="admin"),
    NavigationEntry("Users and access", "Users roles accounts", "users", minimum_role="admin"),
    NavigationEntry("API clients", "REST credentials tokens", "api_clients_admin", minimum_role="admin"),
    NavigationEntry("Audit log", "Audit evidence events retention", "audit_log", minimum_role="admin"),
    NavigationEntry("Service delivery and governance", "Routing SLA freeze teams", "itil_admin", minimum_role="admin"),
    NavigationEntry("Integrations", "Webhooks monitoring RT import delivery", "integrations_admin", minimum_role="admin"),
    NavigationEntry("Automation rules", "Workflow published executions", "workflows_admin", minimum_role="admin"),
    NavigationEntry("Scheduled automation", "Recurring workflow interval schedule", "workflows_scheduled", minimum_role="admin"),
    NavigationEntry("Ticket defaults", "Default priority category Service delivery and governance", "itil_admin_section", {"section": "ticket-defaults"}, "admin"),
    NavigationEntry("Catalog routing", "Fulfillment team catalog items Service delivery and governance", "itil_admin_section", {"section": "catalog"}, "admin"),
    NavigationEntry("Team aliases", "Support group name aliases Service delivery and governance", "itil_admin_section", {"section": "team-aliases"}, "admin"),
    NavigationEntry("Team managers", "Support group manager assignment Service delivery and governance", "itil_admin_section", {"section": "team-managers"}, "admin"),
    NavigationEntry("Governance groups", "CCB executive approval group setup Service delivery and governance", "itil_admin_section", {"section": "governance-groups"}, "admin"),
    NavigationEntry("Change approval policy", "Normal Standard change authorization Service delivery and governance", "itil_admin_section", {"section": "change-approval-policy"}, "admin"),
    NavigationEntry("Change Control Board", "CCB membership approval Service delivery and governance", "itil_admin_section", {"section": "ccb"}, "admin"),
    NavigationEntry("Executive approval authority", "Executive change sign-off Service delivery and governance", "itil_admin_section", {"section": "executive-approval"}, "admin"),
    NavigationEntry("Change freeze windows", "Blackout period schedule block Service delivery and governance", "itil_admin_section", {"section": "change-freeze"}, "admin"),
    NavigationEntry("Service offerings", "Business service catalog Service delivery and governance", "itil_admin_section", {"section": "service-offerings"}, "admin"),
    NavigationEntry("SLA definitions", "Service level agreement targets Service delivery and governance", "itil_admin_section", {"section": "sla"}, "admin"),
    NavigationEntry("Performance charts", "Response time throughput System health", "system_health", {"_anchor": "performance"}, "admin"),
    NavigationEntry("Application errors", "Error log System health", "system_health", {"_anchor": "application-errors"}, "admin"),
    NavigationEntry("Active users", "Currently signed in System health", "system_health", {"_anchor": "active-users"}, "admin"),
    NavigationEntry("Recovery set", "Backup RPO freshness System health", "system_health", {"_anchor": "recovery-set"}, "admin"),
    NavigationEntry("Client management", "Customer support external clients SysOps", "client_management_home", client_management=True),
    NavigationEntry("Customer tickets", "Client cases conversations replies internal notes", "client_tickets", client_management=True),
    NavigationEntry("Client organizations", "Customer companies accounts", "client_organizations", client_management=True),
    NavigationEntry("Client contacts", "Customer people email phone", "client_contacts", client_management=True),
)


def navigation_entries(setting_group_meta):
    """Return the immutable base catalogue plus current setting categories."""
    setting_entries = []
    for category, (label, description) in setting_group_meta.items():
        if category == "request_tracker_connection":
            setting_entries.append(NavigationEntry(
                label, f"{description} Request Tracker import", "rt_import",
                minimum_role="admin",
            ))
        else:
            setting_entries.append(NavigationEntry(
                label, f"{description} Platform settings", "system_settings_category",
                {"category": category}, "admin",
            ))
    return NAVIGATION_ENTRIES + tuple(setting_entries)
