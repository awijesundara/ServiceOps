"""Generate the official ServiceOps platform user-interface guide."""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "ServiceOps_Platform_User_Interface_Guide.pdf"
GREEN = colors.HexColor("#003E4C")
DARK = colors.HexColor("#002F3A")
AMBER = colors.HexColor("#F9AA3C")
INK = colors.HexColor("#13252B")
MUTED = colors.HexColor("#63767D")
PALE = colors.HexColor("#E8F1F3")
LINE = colors.HexColor("#DDE5E8")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                          fontSize=34, leading=39, textColor=colors.white, alignment=TA_LEFT))
styles.add(ParagraphStyle(name="CoverSub", parent=styles["BodyText"], fontSize=14, leading=21,
                          textColor=colors.HexColor("#C6D4DB")))
styles.add(ParagraphStyle(name="Chapter", parent=styles["Heading1"], fontName="Helvetica-Bold",
                          fontSize=24, leading=29, textColor=DARK, spaceAfter=12))
styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
                          fontSize=15, leading=19, textColor=GREEN, spaceBefore=11, spaceAfter=6))
styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontSize=9.6, leading=14,
                          textColor=INK, spaceAfter=7))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=11,
                          textColor=MUTED))
styles.add(ParagraphStyle(name="Callout", parent=styles["BodyText"], fontSize=9.5, leading=14,
                          leftIndent=10, rightIndent=10, borderColor=GREEN, borderWidth=1,
                          borderPadding=9, backColor=PALE, textColor=INK, spaceBefore=8, spaceAfter=8))


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9 * mm, "ServiceOps Platform User Interface Guide")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def bullets(items):
    return [Paragraph(f"• {item}", styles["Body"]) for item in items]


def feature_table(rows, widths=None):
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 11),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8F8")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


chapters = [
    ("1. Platform overview",
     "ServiceOps is a Docker-deployable enterprise service-management platform that connects IT service management, operations, employee self-service, governance, security work, customer cases, HR cases, portfolio work, and field service through shared records and role-aware workspaces.",
     [
         ("Experience principles", ["One navigation shell across all workspaces", "Role-aware access and landing pages",
                                    "Persistent work context through favorites and history", "Auditable changes and governed approvals",
                                    "Responsive and accessible interaction"]),
         ("Primary experiences", ["Employee self-service portal", "Agent and manager workspaces", "Change and CCB governance",
                                  "ITIL administration", "Operational analytics and visual work board"]),
     ]),
    ("2. Sign in and account roles",
     "Sign in at the deployment URL with an active ServiceOps account. The navigation and available actions change with the assigned role and team membership.",
     [
         ("Roles", ["Requester: self-service requests, own tickets, knowledge, notifications, and attachments",
                    "Agent: fulfillment queues, operational records, task updates, knowledge authoring, and analytics",
                    "Manager: agent capabilities plus team management and approval authority",
                    "Administrator: users, configuration, audit, CMDB, assets, and platform-wide governance"]),
         ("Manager accounts", ["CoreApps, Database, Network, Windows, Unix, and SSD each have a dedicated manager",
                               "Every team manager is synchronized into the Change Control Board"]),
     ]),
    ("3. Unified navigation",
     "The unified shell combines persistent application navigation with a global top bar so users can move between workspaces without losing context.",
     [
         ("Top bar", ["Global search", "Favorites", "History", "Unread notifications",
                      "Favorite-this-page action", "Help Center", "Display and accessibility preferences"]),
         ("Application navigation", ["Dashboard", "Visual task board", "ITSM queues", "Catalog and knowledge",
                                     "Enterprise workspaces", "Operations", "Analytics", "Administration"]),
         ("Responsive behavior", ["Collapse the sidebar to free horizontal space", "Mobile layouts convert navigation to a compact shell"]),
     ]),
    ("4. Landing page and dashboard",
     "The dashboard provides a role-aware start-of-day view with volume indicators and recently updated work. Users can choose Dashboard, Visual Task Board, or All Workspaces as their start page.",
     [
         ("Operational indicators", ["Incident, request, and change totals", "Open-work total", "Recently updated records"]),
         ("Role behavior", ["Requesters see their own work", "Fulfillers and managers see operational queues",
                            "Administrators receive platform-wide visibility"]),
     ]),
    ("5. Global search",
     "Use the search field in the unified navigation to search across major ServiceOps record families from one place.",
     [
         ("Indexed experiences", ["Incident, request, and change numbers and content", "Knowledge articles",
                                  "Enterprise records", "Configuration items"]),
         ("Result design", ["Record-type badge", "Primary label", "State or category context", "Direct navigation"]),
     ]),
    ("6. Favorites and history",
     "Favorites and recent history are stored per user in PostgreSQL and follow the user across browsers and sessions.",
     [
         ("Favorites", ["Select the star on any page", "Open saved pages from the top-bar menu",
                        "Select the star again to remove the favorite"]),
         ("History", ["Authenticated page visits are recorded automatically", "The most recent pages appear first",
                      "Static assets and internal service endpoints are excluded"]),
     ]),
    ("7. Lists, filters, and queues",
     "Queue pages provide consistent table structures for scanning and opening records. ITSM and enterprise queues support query and state filtering.",
     [
         ("List conventions", ["Record number links", "State badges", "Priority indicators", "Requester and assignee context",
                               "Responsive horizontal scrolling", "Purposeful empty states"]),
         ("Queue access", ["Requesters are restricted to their records", "Agents and managers access fulfillment work",
                           "Administrators receive complete access"]),
     ]),
    ("8. Record forms and activity",
     "Record pages combine operational facts, lifecycle controls, activity, governed decisions, service-level targets, checklists, and files.",
     [
         ("Activity", ["Chronological comments", "Author and timestamp", "New comment composer"]),
         ("Record controls", ["State, priority, risk, assignment, and team ownership", "Role-enforced updates",
                              "Audit events for meaningful changes"]),
     ]),
    ("9. Attachments and checklists",
     "Ticket attachments are saved in a dedicated Docker volume while metadata and access rules remain in PostgreSQL. Checklists provide small, auditable execution steps.",
     [
         ("Attachments", ["20 MB request limit", "Secure generated storage names", "Original-name downloads",
                          "Requester ownership validation", "Persistent serviceops_uploads volume"]),
         ("Checklists", ["Ordered ticket steps", "Complete/incomplete toggling", "Manager and fulfiller editing"]),
     ]),
    ("10. Visual task board",
     "The task board renders live ticket states as lifecycle lanes. Authorized users drag cards between lanes; the source ticket, audit history, and SLA stage update together.",
     [
         ("Lanes", ["New", "In Progress", "Pending", "Resolved", "Closed"]),
         ("Cards", ["Priority", "record number", "summary", "assignee"]),
         ("Governance", ["Drag actions require agent, manager, or administrator role", "Requesters receive a read-only board"]),
     ]),
    ("11. Personalization and accessibility",
     "Display preferences are stored per user and applied by the server on every authenticated page.",
     [
         ("Preferences", ["System, light, or dark theme", "Comfortable or compact density", "80–140% font scaling",
                          "High contrast", "Reduced motion", "Pinned navigation", "Preferred start page"]),
         ("Accessibility foundation", ["Semantic labels", "Keyboard-accessible native controls", "Responsive reflow",
                                       "Reduced-motion override", "High-contrast design tokens"]),
     ]),
    ("12. Notifications",
     "The notification inbox brings approval requests and workflow outcomes into the unified shell. An unread counter indicates pending messages.",
     [
         ("Lifecycle", ["Notifications are user-specific", "Opening the inbox marks messages read",
                        "Approval-chain activation creates approver notifications", "Approval outcomes notify requesters"]),
     ]),
    ("13. Employee self-service",
     "The self-service experience combines catalog ordering, knowledge search, request tracking, comments, and file exchange.",
     [
         ("Catalog", ["Category, description, delivery estimate, and approval requirement", "Request-detail variables",
                      "Direct transition into REQ/RITM/SCTASK fulfillment"]),
         ("Knowledge", ["Full-text title and body search", "Category context", "Role-restricted publishing"]),
     ]),
    ("14. Request fulfillment",
     "ServiceOps follows the REQ → RITM → SCTASK hierarchy. Requested items carry variables, due dates, approvals, and SLAs; catalog tasks carry assignment and work notes.",
     [
         ("State roll-up", ["SCTASK completion updates RITM", "All completed RITMs close the REQ",
                            "Incomplete work propagates incomplete state"]),
         ("Approval path", ["Manager approval", "Fulfillment authorization", "Task creation after final approval"]),
     ]),
    ("15. Incident and problem work",
     "Incident queues support classification, priority, assignment, activity, SLA tracking, and resolution. Problem workspaces capture root-cause and known-error work for recurring disruption.",
     [
         ("Incident lifecycle", ["New", "In Progress", "Pending", "Resolved", "Closed"]),
         ("Operational context", ["Priority-based SLAs", "Assignee and requester", "Checklist and evidence", "Audit history"]),
     ]),
    ("16. Change and CCB governance",
     "Change records capture the implementation evidence required for controlled delivery and route decisions through the owning team and Change Control Board.",
     [
         ("Change detail", ["Normal, Standard, or Emergency type", "Owning IT team", "Impact and numeric risk",
                            "Affected CI", "Planned dates", "Implementation, test, and backout plans"]),
         ("Approval chain", ["Owning-team manager assessment", "Weekly CCB authorization for Normal and Emergency changes",
                             "Six CCB manager votes", "Four-of-six majority", "Immediate rejection behavior"]),
         ("Conflict detection", ["Overlapping schedules", "Same affected configuration item", "Recorded conflict outcome"]),
     ]),
    ("17. Service levels",
     "SLA definitions attach task-SLA instances by record type and priority. ServiceOps retains start, pause, resume, completion, breach target, and accumulated pause duration.",
     [
         ("Default commitments", ["P1 response", "P1/P2/P3 resolution", "Catalog fulfillment"]),
         ("Clock behavior", ["Pending and On Hold pause clocks", "Resume shifts breach target",
                             "Resolution and closure complete the timer"]),
     ]),
    ("18. CMDB and service mapping",
     "The CMDB workspace stores configuration items, operational state, ownership, environment, addresses, and typed dependencies.",
     [
         ("Configuration context", ["Business applications", "Application services", "Databases and infrastructure classes",
                                    "Operational, degraded, down, maintenance, and retired states"]),
         ("Relationships", ["Parent/child dependencies", "Service-impact context for change and operations"]),
     ]),
    ("19. Enterprise workspaces",
     "Shared enterprise records provide consistent lifecycle, risk, priority, assignment, due-date, and approval behavior across additional domains.",
     [
         ("Domains", ["Customer service", "HR service delivery", "Security operations", "Risk and compliance",
                      "Strategic portfolio", "Field service", "IT operations events", "Releases"]),
     ]),
    ("20. ITIL administration",
     "Administrators manage the service-management foundation from one workspace.",
     [
         ("Configuration views", ["IT fulfillment teams", "Team managers", "CCB membership and chair",
                                  "Support and approval groups", "Service offerings", "SLA definitions"]),
         ("Current IT organization", ["CoreApps", "Database", "Network", "Windows", "Unix", "SSD"]),
     ]),
    ("21. Help and onboarding",
     "The Help Center provides task-oriented guidance and a short interactive tour of unified navigation.",
     [
         ("Guidance topics", ["Search and navigation", "Governed change submission", "Visual board usage",
                              "Accessibility and personalization"]),
     ]),
    ("22. Security and audit",
     "Authentication, active-account checks, role decorators, ownership restrictions, protected downloads, and server-side validation enforce access.",
     [
         ("Audit coverage", ["Login", "record creation and update", "approvals and rejection", "board movement",
                             "attachment upload", "change conflict checks", "preference updates"]),
         ("Deployment controls", ["Password hashing", "non-root application process", "private database network",
                                  "health checks", "external HTTPS proxy recommendation"]),
     ]),
    ("23. Docker deployment and operations",
     "The production stack uses a hardened Gunicorn application service with either bundled PostgreSQL 16 or a separately managed PostgreSQL server. The first-install menu generates secrets, validates the host, starts the selected architecture, and waits for readiness.",
     [
         ("Installation modes", ["Bundled database for a simple single-server deployment",
                                 "External database for managed PostgreSQL and separated infrastructure ownership"]),
         ("Operations CLI", ["Health and diagnostics", "Logs and restart", "Bundled database and upload backups",
                             "Guarded restore", "Health-gated updates"]),
         ("Resources", ["serviceops-app image", "serviceops-app-1 and optional serviceops-db-1 containers",
                        "serviceops_postgres_data in bundled mode", "serviceops_uploads"]),
         ("Verification", ["Preflight and Compose validation", "GET /health", "database query",
                           "upload-volume write test", "application logs", "automated pytest suite"]),
     ]),
    ("24. Source-guide mapping and boundaries",
     "The Australia UI guide was reviewed as a feature reference. ServiceOps implements independent equivalents where they map to this product and classifies vendor-specific runtimes honestly.",
     [
         ("Implemented equivalents", ["Unified navigation", "workspaces", "lists and forms", "portal", "favorites and history",
                                      "notifications", "themes", "accessibility", "attachments", "task boards", "help and onboarding"]),
         ("Vendor-specific or external", ["UI Builder and proprietary widget runtime", "Jelly and vendor scripting APIs",
                                          "native mobile publishing", "telephony and chat routing", "voice guidance",
                                          "predictive and generative AI services"]),
     ]),
    ("25. Kubernetes deployment",
     "ServiceOps includes a production-oriented Helm chart. Enterprise Production uses replicated application pods, an external highly available PostgreSQL service, shared upload storage, TLS ingress, and cluster observability.",
     [
         ("Workload safeguards", ["Restricted Pod Security", "non-root process", "read-only root filesystem",
                                  "startup, readiness, and liveness probes", "rolling update", "PodDisruptionBudget",
                                  "topology spread", "resource controls", "NetworkPolicy", "optional HPA"]),
         ("Installation", ["Immutable registry image", "production values file", "Kubernetes preflight",
                           "atomic Helm upgrade", "rollout wait", "packaged Helm health test"]),
     ]),
    ("26. Production operations",
     "The complete operations manual covers deployment decisions, identity, backups, recovery, upgrades, rollback, monitoring, incident response, and production acceptance.",
     [
         ("Recovery", ["PostgreSQL point-in-time recovery", "matching upload recovery set",
                       "off-cluster encrypted retention", "quarterly restore evidence"]),
         ("Release assurance", ["staging regression", "manifest lint and render", "load and soak testing",
                                "database failover", "node drain", "atomic rollout", "tested data rollback"]),
     ]),
    ("27. JNX visual system",
     "The interface retains the unified enterprise patterns documented in the source UI guide while applying the company palette consistently.",
     [
         ("Palette", ["Deep teal #003E4C for navigation, identity, links, and focus context",
                      "Warm amber #F9AA3C for selected emphasis, workflow cues, and warnings"]),
         ("Interaction", ["persistent application navigator", "unified search bar", "dense operational tables",
                          "workspaces and panels", "visible keyboard focus", "responsive and accessible themes"]),
     ]),
]


def build():
    doc = SimpleDocTemplate(str(OUTPUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
                            topMargin=19 * mm, bottomMargin=20 * mm,
                            title="ServiceOps Platform User Interface Guide",
                            author="ServiceOps")
    story = []
    cover = Table([[Paragraph("SERVICEOPS", styles["Small"])],
                   [Spacer(1, 28 * mm)],
                   [Paragraph("Platform User<br/>Interface Guide", styles["CoverTitle"])],
                   [Spacer(1, 6 * mm)],
                   [Paragraph("Unified navigation, workspaces, ITIL workflows, accessibility, self-service, and administration", styles["CoverSub"])],
                   [Spacer(1, 42 * mm)],
                   [Paragraph("Version 1.0 · 25 July 2026", styles["CoverSub"])]],
                  colWidths=[174 * mm], rowHeights=[12 * mm, 28 * mm, None, 8 * mm, None, 42 * mm, 14 * mm])
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), DARK),
                               ("LEFTPADDING", (0, 0), (-1, -1), 15 * mm),
                               ("RIGHTPADDING", (0, 0), (-1, -1), 15 * mm),
                               ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
                               ("TEXTCOLOR", (0, 0), (-1, -1), colors.white)]))
    story += [cover, PageBreak(), Paragraph("Contents", styles["Chapter"])]
    toc_rows = [["Chapter", "Topic"]]
    for index, (title, _, _) in enumerate(chapters, 1):
        number, topic = title.split(". ", 1)
        toc_rows.append([number, topic])
    story += [feature_table(toc_rows, [20 * mm, 145 * mm]), PageBreak()]
    for index, (title, intro, sections) in enumerate(chapters):
        story += [Paragraph(title, styles["Chapter"]), Paragraph(intro, styles["Body"])]
        for heading, items in sections:
            story.append(Paragraph(heading, styles["Section"]))
            story.extend(bullets(items))
        if index == 0:
            story.append(Paragraph("This guide documents the behavior of the running ServiceOps product. It is an original work and does not reproduce third-party manual text or imagery.", styles["Callout"]))
        story.append(PageBreak())
    rows = [["Capability family", "ServiceOps status"],
            ["Unified navigation, landing pages, lists, forms", "Implemented"],
            ["Favorites, history, notifications, global search", "Implemented"],
            ["Themes, density, accessibility, responsive UI", "Implemented"],
            ["Service portal, knowledge, catalog, requests", "Implemented"],
            ["Visual task board, attachments, checklists", "Implemented"],
            ["Guided help and onboarding", "Implemented"],
            ["Vendor UI Builder, Jelly, proprietary widget APIs", "Not applicable; independent Flask/Jinja stack"],
            ["Telephony, chat routing, native mobile, hosted AI", "External integration required"]]
    story += [Paragraph("Appendix A. Capability summary", styles["Chapter"]),
              feature_table(rows, [78 * mm, 87 * mm]), Spacer(1, 8 * mm),
              Paragraph("For the maintained implementation matrix, see docs/UI_CAPABILITY_MAPPING.md in the ServiceOps repository.", styles["Callout"])]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    build()
