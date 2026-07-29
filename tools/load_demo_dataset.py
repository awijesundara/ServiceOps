#!/usr/bin/env python3
"""Load a realistic, disposable demo dataset for manual/local testing.

This seeds a full-depth CMDB (business services -> applications -> databases
-> servers -> network/storage, with dependency relationships), a roster of
per-team users, and a representative spread of INC/PRB/CHG/REQ/RITM/SCTASK/KB
records across open and closed states, so a reviewer can exercise every
screen without hand-creating records first.

Never run this against a production database. It is intentionally NOT called
by application startup, and requires --confirm-non-production to run.

Scope note: seeded changes/problems set a descriptive `state` directly rather
than driving the live ApprovalChain/ApprovalGate/ApprovalVote engine, so the
records are visible and browsable immediately without a pending approval
blocking every screen. To test the *live* approval workflow itself, submit a
new change/request through the UI against this seeded data — that exercises
the real engine end-to-end. CCB and manager approvers below already exist
and are eligible.
"""

import argparse
import random
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from werkzeug.security import generate_password_hash

from app import (
    Asset, CatalogItem, CatalogItemRouting, CatalogRequest, CatalogTask,
    ChangeGovernance, ChangeOwnership, ConfigurationItem, CIRelationship,
    EnterpriseRecord, GroupMember, Knowledge, OperationalTask, RequestedItem,
    ServiceOffering, SupportGroup, TaskCI, TaskHistory, Ticket,
    TicketAssignmentGroup, User, create_app, db, now, sequence_number,
)

RNG = random.Random(20260729)

TEAM_USERS = {
    "CoreApps": [("j.tanaka", "Jun Tanaka", "manager"), ("s.iwata", "Saori Iwata", "agent")],
    "Database": [("m.chen", "Mei Chen", "manager"), ("r.singh", "Raj Singh", "agent")],
    "Network": [("l.moreau", "Léa Moreau", "manager"), ("d.osei", "David Osei", "agent")],
    "Windows": [("k.nakamura", "Kenji Nakamura", "manager"), ("a.silva", "Ana Silva", "agent")],
    "Unix": [("t.oliveira", "Tiago Oliveira", "manager"), ("f.khan", "Fatima Khan", "agent")],
    "SSD": [("h.park", "Hana Park", "manager"), ("c.nilsson", "Carl Nilsson", "agent")],
}
REQUESTERS = [
    ("e.wright", "Emma Wright"), ("o.dubois", "Olivier Dubois"),
    ("n.patel", "Nisha Patel"), ("b.reyes", "Bianca Reyes"), ("s.kim", "Seo-yeon Kim"),
]

CMDB_TREE = [
    {
        "service": ("Customer Portal", "Business Application", "Critical"),
        "apps": [("Portal Web App", "Web Application", "High", "Nginx/Node 20")],
        "dbs": [("PORTALDB01", "PostgreSQL 16", "High")],
        "servers": [("APPSRV01", "app"), ("APPSRV02", "app")],
    },
    {
        "service": ("Payroll Service", "Business Application", "Critical"),
        "apps": [("Payroll Engine", "Application", "High", "Java 21 / Spring Boot")],
        "dbs": [("PAYROLLDB01", "Oracle 19c", "Critical")],
        "servers": [("APPSRV03", "app"), ("DBSRV01", "db")],
    },
    {
        "service": ("Email & Collaboration", "Business Service", "High"),
        "apps": [("Exchange Online Connector", "Middleware", "Medium", "PowerShell/Graph API")],
        "dbs": [],
        "servers": [("APPSRV04", "app")],
    },
]
NETWORK_CIS = [
    ("CORE-SW01", "Network Device", "Cisco", "Catalyst 9300", "DC1 Rack 4"),
    ("EDGE-FW01", "Network Device", "Palo Alto", "PA-3260", "DC1 Rack 1"),
    ("LB01", "Network Device", "F5", "BIG-IP i4800", "DC1 Rack 2"),
    ("VPN-GW01", "Network Device", "Cisco", "ASA 5525-X", "DC1 Rack 1"),
]
STORAGE_CIS = [
    ("SAN01", "Storage", "NetApp", "AFF A400", "DC1 Rack 6"),
    ("BACKUP-NAS01", "Storage", "Synology", "RS4021xs+", "DC1 Rack 7"),
]


def get_or_create_user(username, name, role, group=None, group_role="member"):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(
            username=username, name=name, email=f"{username}@demo.serviceops.invalid",
            password_hash=generate_password_hash(username), role=role,
            title=role.capitalize(), department=group.name if group else "",
        )
        db.session.add(user)
        db.session.flush()
    if group:
        if not GroupMember.query.filter_by(group_id=group.id, user_id=user.id).first():
            db.session.add(GroupMember(group_id=group.id, user_id=user.id, role=group_role))
        if group_role == "manager":
            group.manager_id = user.id
    return user


def make_ci(name, ci_class, environment, criticality, owner, support_group,
           vendor=None, model=None, location="DC1", lifecycle="In Use",
           status="Operational", ip=None, serial=None, discovery="Manual"):
    ci = ConfigurationItem.query.filter_by(name=name).first()
    if ci:
        return ci
    ci = ConfigurationItem(
        name=name, ci_class=ci_class, environment=environment,
        business_criticality=criticality, operational_status=status,
        lifecycle_state=lifecycle, owner_id=owner.id, support_group_id=support_group.id if support_group else None,
        vendor=vendor, model=model, location=location, ip_address=ip, serial_number=serial,
        discovery_source=discovery, install_date=now().date() - timedelta(days=RNG.randint(90, 900)),
        description=f"{ci_class} supporting {name}.",
    )
    db.session.add(ci)
    db.session.flush()
    return ci


def link(parent, child, relationship_type="Depends on"):
    existing = CIRelationship.query.filter_by(
        parent_id=parent.id, child_id=child.id, relationship_type=relationship_type,
    ).first()
    if not existing:
        db.session.add(CIRelationship(
            parent_id=parent.id, child_id=child.id, relationship_type=relationship_type,
        ))


def build_users_and_teams():
    ccb = SupportGroup.query.filter_by(name="Change Control Board").one()
    teams = {}
    for team_name, members in TEAM_USERS.items():
        team = SupportGroup.query.filter_by(name=team_name).one()
        teams[team_name] = team
        for username, name, role in members:
            group_role = "manager" if role == "manager" else "member"
            user = get_or_create_user(username, name, role, team, group_role)
            if group_role == "manager" and not GroupMember.query.filter_by(
                group_id=ccb.id, user_id=user.id
            ).first():
                db.session.add(GroupMember(group_id=ccb.id, user_id=user.id, role="CCB approver"))
    requesters = [get_or_create_user(u, n, "requester") for u, n in REQUESTERS]
    db.session.flush()
    return teams, requesters


def build_cmdb(teams, admin):
    all_cis = {}
    for tree in CMDB_TREE:
        service_name, service_class, criticality = tree["service"]
        support_group = teams.get("CoreApps")
        service = make_ci(
            service_name, service_class, "Production", criticality, admin, support_group,
            location="Business Service Catalog", discovery="Manual",
        )
        all_cis[service_name] = service
        for app_name, app_class, app_crit, tech in tree["apps"]:
            app_ci = make_ci(
                app_name, app_class, "Production", app_crit, admin, support_group,
                vendor=tech, discovery="Discovery scan",
            )
            all_cis[app_name] = app_ci
            link(service, app_ci, "Depends on")
        for db_name, engine, db_crit in tree["dbs"]:
            db_group = teams.get("Database")
            db_ci = make_ci(
                db_name, "Database", "Production", db_crit, admin, db_group,
                vendor=engine.split()[0], model=engine, discovery="Discovery scan",
            )
            all_cis[db_name] = db_ci
            for app_name, *_ in tree["apps"]:
                link(all_cis[app_name], db_ci, "Depends on")
        for server_name, owning_team in tree["servers"]:
            team = teams.get("Windows" if owning_team == "app" else "Unix")
            server_ci = make_ci(
                server_name, "Server", "Production", "Medium", admin, team,
                vendor="Dell", model="PowerEdge R750", serial=f"SN-{server_name}",
                ip=f"10.20.{RNG.randint(1,30)}.{RNG.randint(2,250)}", discovery="Discovery scan",
            )
            all_cis[server_name] = server_ci
            for app_name, *_ in tree["apps"]:
                link(all_cis[app_name], server_ci, "Runs on")
            for db_name, *_ in tree["dbs"]:
                link(all_cis[db_name], server_ci, "Runs on")

    network_group = teams.get("Network")
    for name, ci_class, vendor, model, location in NETWORK_CIS:
        ci = make_ci(
            name, ci_class, "Production", "High", admin, network_group,
            vendor=vendor, model=model, location=location, discovery="Discovery scan",
        )
        all_cis[name] = ci
    storage_group = teams.get("SSD")
    for name, ci_class, vendor, model, location in STORAGE_CIS:
        ci = make_ci(
            name, ci_class, "Production", "High", admin, storage_group,
            vendor=vendor, model=model, location=location, discovery="Discovery scan",
        )
        all_cis[name] = ci

    for server_name in ["APPSRV01", "APPSRV02", "APPSRV03", "APPSRV04", "DBSRV01"]:
        link(all_cis[server_name], all_cis["CORE-SW01"], "Connects to")
        link(all_cis[server_name], all_cis["SAN01"], "Stores on")
        link(all_cis[server_name], all_cis["BACKUP-NAS01"], "Backed up by")
    link(all_cis["CORE-SW01"], all_cis["EDGE-FW01"], "Connects to")
    link(all_cis["LB01"], all_cis["APPSRV01"], "Balances")
    link(all_cis["LB01"], all_cis["APPSRV02"], "Balances")
    db.session.flush()
    return all_cis


def build_incidents(cis, teams, requesters, agents_by_team):
    scenarios = [
        ("Customer Portal login failures for a subset of users", "P2", "Resolved",
         "Portal Web App", "Windows"),
        ("Payroll batch job did not complete overnight", "P1", "Resolved", "Payroll Engine", "Unix"),
        ("PORTALDB01 replication lag alert", "P3", "Closed", "PORTALDB01", "Database"),
        ("Slow response times on Customer Portal during peak hours", "P2", "In Progress",
         "Portal Web App", "Windows"),
        ("VPN gateway intermittent drops for remote staff", "P3", "New", "VPN-GW01", "Network"),
        ("Exchange Online connector authentication errors", "P2", "In Progress",
         "Exchange Online Connector", "CoreApps"),
        ("SAN01 disk predictive failure alert", "P3", "New", "SAN01", "SSD"),
        ("APPSRV02 high CPU utilization", "P4", "Closed", "APPSRV02", "Windows"),
    ]
    created = []
    for title, priority, state, ci_name, team_name in scenarios:
        if Ticket.query.filter_by(title=title).first():
            continue
        team = teams[team_name]
        requester = RNG.choice(requesters)
        assignee = agents_by_team.get(team_name)
        ticket = Ticket(
            number=sequence_number(Ticket, "INC"), kind="incident", title=title,
            description=f"{title}. Reported via Self-service.", priority=priority, state=state,
            impact="High" if priority in ("P1", "P2") else "Medium",
            urgency="High" if priority in ("P1", "P2") else "Medium",
            category="Software" if "portal" in title.lower() or "payroll" in title.lower() else "Infrastructure",
            requester_id=requester.id, assignee_id=assignee.id if assignee else None,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(TicketAssignmentGroup(ticket_id=ticket.id, group_id=team.id))
        ci = cis.get(ci_name)
        if ci:
            db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=ci.id, relationship_role="Affected CI"))
        log_history_entry = TaskHistory(
            target_type="ticket", target_id=ticket.id, actor_id=assignee.id if assignee else requester.id,
            event="Incident created", details=f"{ticket.number} opened as {priority}.",
        )
        db.session.add(log_history_entry)
        created.append(ticket)
    return created


def build_problems(cis, teams, agents_by_team):
    scenarios = [
        ("Recurring Customer Portal login failures", "Root cause analysis", "Windows",
         ["Reproduce failure in staging", "Review authentication service logs"]),
        ("Payroll batch job intermittent overruns", "Known error", "Unix",
         ["Profile batch job runtime", "Engage vendor support for Payroll Engine"]),
        ("PORTALDB01 replication instability", "Root cause analysis", "Database",
         ["Review replication configuration", "Validate network path to replica"]),
    ]
    for title, record_type, team_name, tasks in scenarios:
        if EnterpriseRecord.query.filter_by(title=title).first():
            continue
        team = teams[team_name]
        assignee = agents_by_team.get(team_name)
        record = EnterpriseRecord(
            number=sequence_number(EnterpriseRecord, "PRB"), domain="problem", record_type=record_type,
            title=title, description=f"{title}. Investigation opened after repeated related incidents.",
            state="In Progress", priority="P3", risk="Medium",
            requester_id=assignee.id, assignee_id=assignee.id,
        )
        db.session.add(record)
        db.session.flush()
        for index, task_title in enumerate(tasks, 1):
            task = OperationalTask(
                number=f"PTASK{record.id:04d}{index:02d}", task_kind="problem",
                parent_type="enterprise", parent_id=record.id, title=task_title,
                task_type="Investigation", state="Open" if index > 1 else "Closed",
                sequence=index, assignment_group_id=team.id, assignee_id=assignee.id if assignee else None,
            )
            db.session.add(task)


def build_changes(cis, teams, agents_by_team, admin):
    scenarios = [
        ("Upgrade PORTALDB01 to PostgreSQL 16.4", "Normal", 60, "Database", "PORTALDB01",
         "Scheduled", ["Apply minor version upgrade", "Run post-upgrade validation queries"]),
        ("Emergency firewall rule rollback on EDGE-FW01", "Emergency", 85, "Network", "EDGE-FW01",
         "Implemented", ["Roll back rule set", "Confirm connectivity restored"]),
        ("Deploy standard laptop imaging update", "Standard", 15, "Windows", "APPSRV01",
         "Closed", ["Push updated image to deployment share"]),
    ]
    for title, change_type, risk, team_name, ci_name, state, tasks in scenarios:
        if Ticket.query.filter_by(title=title).first():
            continue
        team = teams[team_name]
        assignee = agents_by_team.get(team_name)
        ticket = Ticket(
            number=sequence_number(Ticket, "CHG"), kind="change", title=title,
            description=f"{title}. Governed change with implementation, test, and backout plans on file.",
            priority="P3" if risk < 70 else "P2", state=state, impact="Medium", urgency="Medium",
            category="Infrastructure", requester_id=assignee.id, assignee_id=assignee.id,
        )
        db.session.add(ticket)
        db.session.flush()
        db.session.add(ChangeOwnership(ticket_id=ticket.id, group_id=team.id))
        ci = cis.get(ci_name)
        db.session.add(ChangeGovernance(
            ticket_id=ticket.id, change_type=change_type, risk_score=risk, impact="Medium",
            implementation_plan="See attached runbook; executed via change tasks below.",
            test_plan="Post-change validation checklist executed by the assigned team.",
            backout_plan="Restore prior configuration/snapshot if validation fails.",
            planned_start=now() - timedelta(days=2), planned_end=now() - timedelta(days=2, hours=-2),
            ci_id=ci.id if ci else None, ccb_required=(change_type != "Standard"),
        ))
        if ci:
            db.session.add(TaskCI(target_type="ticket", target_id=ticket.id, ci_id=ci.id, relationship_role="Affected CI"))
        for index, task_title in enumerate(tasks, 1):
            db.session.add(OperationalTask(
                number=f"CTASK{ticket.id:04d}{index:02d}", task_kind="change",
                parent_type="ticket", parent_id=ticket.id, title=task_title,
                task_type="Implementation", state="Closed" if state in ("Implemented", "Closed") else "Open",
                sequence=index, assignment_group_id=team.id, assignee_id=assignee.id if assignee else None,
            ))


def build_requests(teams, requesters, admin):
    laptop = CatalogItem.query.filter(CatalogItem.name.ilike("%laptop%")).first()
    software = CatalogItem.query.filter(CatalogItem.name.ilike("%software%")).first()
    if not laptop or CatalogRequest.query.filter_by(state="Closed Complete").first():
        return
    windows = teams["Windows"]
    for item, requester, state, stage in [
        (laptop, requesters[0], "Closed Complete", "Fulfilled"),
        (software, requesters[1], "Open", "Fulfillment In Progress"),
    ]:
        if not item:
            continue
        req = CatalogRequest(
            number=sequence_number(CatalogRequest, "REQ"), requested_by_id=requester.id,
            requested_for_id=requester.id, state=state,
        )
        db.session.add(req)
        db.session.flush()
        ritm = RequestedItem(
            number=sequence_number(RequestedItem, "RITM"), request_id=req.id,
            catalog_item_id=item.id, state=state, stage=stage,
        )
        db.session.add(ritm)
        db.session.flush()
        task = CatalogTask(
            number=sequence_number(CatalogTask, "SCTASK"), requested_item_id=ritm.id,
            title=f"Fulfill {item.name}", state="Closed" if state == "Closed Complete" else "Open",
            assignment_group_id=windows.id,
        )
        db.session.add(task)


def build_knowledge(admin):
    articles = [
        ("Resetting a Customer Portal user password", "Access", "1. Confirm requester identity.\n2. Reset via admin console.\n3. Notify user."),
        ("Payroll Engine batch job troubleshooting", "Applications", "Check job queue depth, review Payroll Engine logs, and confirm DB connectivity to PAYROLLDB01."),
        ("VPN gateway connectivity checklist", "Network", "Verify VPN-GW01 service status, check certificate expiry, confirm client configuration profile version."),
        ("Standard change: laptop imaging update", "Change Management", "Pre-authorized standard change template for pushing an updated laptop image to the deployment share."),
        ("CMDB data quality guidelines", "Configuration Management", "Every CI must have an owner, support group, environment, and lifecycle state. Discovery-sourced CIs should be reconciled monthly."),
    ]
    for title, category, body in articles:
        if Knowledge.query.filter_by(title=title).first():
            continue
        db.session.add(Knowledge(title=title, category=category, body=body, author_id=admin.id))


def load_dataset():
    admin = User.query.filter_by(username="admin").one()
    teams, requesters = build_users_and_teams()
    agents_by_team = {
        name: User.query.filter_by(username=members[1][0]).first()
        for name, members in TEAM_USERS.items()
    }
    cis = build_cmdb(teams, admin)
    build_incidents(cis, teams, requesters, agents_by_team)
    build_problems(cis, teams, agents_by_team)
    build_changes(cis, teams, agents_by_team, admin)
    build_requests(teams, requesters, admin)
    build_knowledge(admin)
    db.session.commit()
    return {
        "configuration_items": ConfigurationItem.query.count(),
        "ci_relationships": CIRelationship.query.count(),
        "tickets": Ticket.query.count(),
        "problems": EnterpriseRecord.query.filter_by(domain="problem").count(),
        "requests": CatalogRequest.query.count(),
        "knowledge_articles": Knowledge.query.count(),
        "users": User.query.count(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-non-production", action="store_true", required=True)
    args = parser.parse_args()
    if not args.confirm_non_production:
        raise SystemExit("Explicit non-production confirmation is required.")
    app = create_app()
    with app.app_context():
        summary = load_dataset()
        print("Demo dataset loaded:")
        for key, value in summary.items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
