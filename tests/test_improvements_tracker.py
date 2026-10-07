"""Improvements tracker items 6-13: AI sensitivity patterns, read-only CMDB
for agents, staying on the page after saving, the company logo page, the
"updating" page during restarts, one LDAP group in several teams, and CMDB
source priority with field mapping."""
import json
from types import SimpleNamespace

from werkzeug.security import generate_password_hash

import app as app_module
from app import ConfigurationItem, GroupMember, PlatformSetting, SupportGroup, User, db, ldap_authenticate
from serviceops_core import ci_precedence, ci_sources, import_changes
from serviceops_core.ai import routing
from test_app import app, client, login  # noqa: F401 - pytest fixtures
from test_ldap_access import ADMINS, DirectoryConn, put, use_directory


def cfg(**overrides):
    values = dict(detect_personal=True, detect_credentials=True, detect_financial=True, sensitive_terms="",
                  sensitive_patterns="", safe_patterns="")
    values.update(overrides)
    return SimpleNamespace(**values)


# 6 -------------------------------------------------------------------------
def test_administrator_patterns_decide_what_is_sensitive():
    assert routing.scan("ticket for EMP-123456", cfg()) == set()
    assert routing.scan("ticket for EMP-123456", cfg(sensitive_patterns=r"EMP-\d{6}")) == {"custom"}
    # The organization's own support address is not a personal detail.
    assert routing.scan("mail support@example.com", cfg()) == {"personal"}
    assert routing.scan("mail support@example.com", cfg(safe_patterns=r"support@example\.com")) == set()
    # A safe pattern only hides what it matches.
    assert routing.scan("support@example.com or anna@x.org", cfg(safe_patterns=r"support@example\.com")) == {"personal"}


def test_invalid_patterns_are_reported_not_used():
    patterns, errors = routing.parse_patterns("ok\n(unclosed\n" + "a" * 300)
    assert [p.pattern for p in patterns] == ["ok"] and len(errors) == 2
    assert routing.scan("(unclosed", cfg(sensitive_patterns="(unclosed")) == set()


def test_ai_settings_save_rejects_a_broken_pattern(client, app):
    login(client)
    response = client.post("/admin/ai/preview", json={"text": "EMP-123456", "sensitive_patterns": "EMP-\\d{6}"})
    assert response.get_json()["sensitive"] is True
    broken = client.post("/admin/ai/preview", json={"text": "x", "sensitive_patterns": "(oops"}).get_json()
    assert broken["pattern_errors"]


# 7 -------------------------------------------------------------------------
def make_agent(app):
    with app.app_context():
        db.session.add(User(username="agent7", name="Agent Seven", email="agent7@test.invalid",
                            password_hash=generate_password_hash("Agent7!password"), role="agent", tenant_id=1))
        ci = ConfigurationItem(name="db01.example.com", ci_class="Server", tenant_id=1, vendor="Dell")
        db.session.add(ci)
        db.session.commit()
        return ci.id


def test_agent_sees_ci_details_read_only_and_cannot_save(client, app):
    ci_id = make_agent(app)
    login(client, "agent7", "Agent7!password")
    page = client.get(f"/cmdb/{ci_id}/edit")
    assert page.status_code == 200
    html = page.get_data(as_text=True)
    assert "db01.example.com" in html and "Dell" in html and "View only" in html
    assert "Save changes" not in html
    assert client.post(f"/cmdb/{ci_id}/edit", data={"name": "renamed", "ci_class": "Server",
                                                    "environment": "Production",
                                                    "operational_status": "Operational"}).status_code == 403
    with app.app_context():
        assert db.session.get(ConfigurationItem, ci_id).name == "db01.example.com"


# 8 -------------------------------------------------------------------------
def test_saving_a_ci_stays_on_the_ci_with_a_confirmation(client, app):
    login(client)
    created = client.post("/cmdb/new", data={"name": "web01.example.com", "ci_class": "Server",
                                             "environment": "Production", "operational_status": "Operational"})
    with app.app_context():
        ci_id = ConfigurationItem.query.filter_by(name="web01.example.com").one().id
    assert created.headers["Location"].endswith(f"/cmdb/{ci_id}/edit")
    saved = client.post(f"/cmdb/{ci_id}/edit", data={"name": "web01.example.com", "ci_class": "Server",
                                                     "environment": "Production",
                                                     "operational_status": "Operational"}, follow_redirects=True)
    assert saved.request.path == f"/cmdb/{ci_id}/edit"
    assert "updated" in saved.get_data(as_text=True)


def test_saving_a_group_stays_on_the_group(client, app):
    login(client)
    response = client.post("/admin/groups/new", data={"name": "Storage", "group_type": "IT Fulfillment"})
    with app.app_context():
        group_id = SupportGroup.query.filter_by(name="Storage").one().id
    assert response.headers["Location"].endswith(f"/admin/groups/{group_id}")


# 9 -------------------------------------------------------------------------
def test_company_logo_is_uploaded_on_the_organization_page(client, app):
    login(client)
    page = client.get("/admin/settings/organization").get_data(as_text=True)
    assert 'name="company_logo"' in page and 'id="company-logo"' in page
    assert client.get("/admin/settings/branding").headers["Location"].endswith("/admin/settings/organization#company-logo")
    import io
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 32
    response = client.post("/admin/settings/organization", data={"company_logo": (io.BytesIO(png), "logo.png")},
                           content_type="multipart/form-data")
    assert response.status_code == 302
    assert 'class="settings-logo-preview"' in client.get("/admin/settings/organization").get_data(as_text=True)


def test_team_aliases_are_managed_on_the_team_managers_page(client):
    login(client)
    page = client.get("/service-operations/settings/team-managers").get_data(as_text=True)
    assert 'id="team-aliases"' in page and "add_support_group_alias" in page and "set_manager" in page
    assert client.get("/service-operations/settings/team-aliases").headers["Location"].endswith(
        "/service-operations/settings/team-managers#team-aliases")


def test_recovery_set_is_set_up_from_system_health(client, app):
    from app import MonitoringSource
    login(client)
    page = client.get("/admin/system-health").get_data(as_text=True)
    assert "Set up the recovery set" in page
    with app.app_context():
        team_id = SupportGroup.query.filter_by(name="Unix").one().id
    response = client.post("/admin/system-health/recovery-setup", data={
        "rpo_hours": "12", "deployment": "kubernetes", "group_id": team_id})
    assert response.status_code == 302
    page = client.get("/admin/system-health").get_data(as_text=True)
    assert "SERVICEOPS_MONITORING_TOKEN=" in page and "backup.alertingSecret" in page
    token = page.split("SERVICEOPS_MONITORING_TOKEN='")[1].split("'")[0]
    with app.app_context():
        source = MonitoringSource.query.filter_by(name="Backup reporter", active=True).one()
        source_id = source.source_id
        assert app_module.setting_int("BACKUP_RPO_HOURS", 24) == 12
    # The token is shown once only, and really records backups.
    assert token not in client.get("/admin/system-health").get_data(as_text=True)
    reported = client.post(f"/api/v1/monitoring/{source_id}/backup-report", json={
        "manifest": "/backups/x.dump", "offsite": "not-configured"}, headers={"Authorization": f"Bearer {token}"})
    assert reported.status_code == 201
    assert "Current" in client.get("/admin/system-health").get_data(as_text=True)
    # Replacing the token revokes the old one.
    client.post("/admin/system-health/recovery-setup", data={"rpo_hours": "12", "deployment": "compose",
                                                             "group_id": team_id})
    assert client.post(f"/api/v1/monitoring/{source_id}/backup-report", json={
        "manifest": "x", "offsite": "archived"}, headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.post("/admin/system-health/recovery-setup", data={
        "rpo_hours": "0", "deployment": "compose", "group_id": team_id}).status_code == 400


# 11 ------------------------------------------------------------------------
def test_service_worker_shows_updating_page_only_for_proxy_errors(client):
    worker = client.get("/service-worker.js").get_data(as_text=True)
    assert "ServiceOps is updating" in worker
    assert 'request.mode === "navigate"' in worker and "X-Request-ID" in worker


# 12 ------------------------------------------------------------------------
def test_one_ldap_group_can_map_to_several_teams(client, app, monkeypatch):
    login(client)
    for name in ("Platform", "Storage"):
        assert client.post("/admin/groups/new", data={
            "name": name, "group_type": "IT Fulfillment", "directory_groups": "gg_serviceops_admins",
        }).status_code == 302
    with app.app_context():
        put("LDAP_ENABLED", "true")
        use_directory(monkeypatch, DirectoryConn([ADMINS]))
        user = ldap_authenticate("jsmith", "correct-horse")
        db.session.commit()
        teams = {m.group.name for m in GroupMember.query.filter_by(user_id=user.id)}
        assert {"Platform", "Storage"} <= teams


def test_merging_teams_that_share_an_ldap_group_keeps_one_mapping(client, app):
    login(client)
    for name in ("Platform", "Storage"):
        client.post("/admin/groups/new", data={"name": name, "group_type": "IT Fulfillment",
                                               "directory_groups": "gg_shared"})
    with app.app_context():
        source = SupportGroup.query.filter_by(name="Platform").one()
        target = SupportGroup.query.filter_by(name="Storage").one()
        app_module.merge_support_group_into(source, target)
        db.session.commit()
        from app import DirectoryGroupMapping
        assert DirectoryGroupMapping.query.filter_by(directory_group="gg_shared").count() == 1


# 13 ------------------------------------------------------------------------
def ci_from(app, source, **values):
    ci = ConfigurationItem(name="sw01", ci_class="Network", tenant_id=1, **values)
    ci_sources.mark(ci, list(values), source)
    db.session.add(ci)
    db.session.flush()
    return ci


def test_default_priority_keeps_spreadsheet_value_over_netbox_and_reports_it(app):
    with app.app_context():
        ci = ci_from(app, "csv", location="Tokyo DC1")
        before = import_changes.snapshot(ci)
        ci.location, summary = "Osaka", {}
        ci_sources.mark(ci, ["location"], "netbox")
        ci_precedence.arbitrate(ci, before, "netbox", summary)
        assert ci.location == "Tokyo DC1" and ci.field_sources["location"] == "csv"
        assert summary["conflicts"][0]["outcome"] == "kept"
        assert summary["conflicts"][0]["other"] == "Osaka"


def test_higher_source_replaces_lower_and_reports_it(app):
    with app.app_context():
        ci = ci_from(app, "netbox", vendor="Cisco")
        before = import_changes.snapshot(ci)
        ci.vendor, summary = "Cisco Systems", {}
        ci_sources.mark(ci, ["vendor"], "snipeit")
        ci_precedence.arbitrate(ci, before, "snipeit", summary)
        assert ci.vendor == "Cisco Systems"
        assert summary["conflicts"][0]["outcome"] == "replaced"


def test_mapped_remote_field_fills_cmdb_field(app):
    with app.app_context():
        db.session.add(PlatformSetting(key="CMDB_FIELD_MAPPINGS", encrypted=False,
                                       value=json.dumps({"snipeit": {"cost_center": "Cost Center"}})))
        ci = ConfigurationItem(name="lap01", ci_class="Laptop", tenant_id=1,
                               attributes={"Snipe-IT: Cost Center": "CC-42"})
        ci_precedence.apply_field_mappings(ci, "snipeit")
        assert ci.cost_center == "CC-42" and ci.field_sources["cost_center"] == "snipeit"


def test_admin_saves_source_rules_and_bad_order_is_refused(client, app):
    login(client)
    assert client.post("/cmdb/import/source-rules", data={
        "precedence": ["csv", "manual", "netbox", "snipeit"], "map_netbox_location": "Site",
    }).status_code == 302
    with app.app_context():
        assert ci_precedence.precedence() == ["csv", "manual", "netbox", "snipeit"]
        assert ci_precedence.field_mappings() == {"netbox": {"location": "Site"}}
    client.post("/cmdb/import/source-rules", data={"precedence": ["csv", "csv", "netbox", "snipeit"]})
    with app.app_context():
        assert ci_precedence.precedence() == ["csv", "manual", "netbox", "snipeit"]
    assert "Source priority and field mapping" in client.get("/cmdb/import").get_data(as_text=True)
