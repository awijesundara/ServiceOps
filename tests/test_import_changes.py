"""Field-level change reporting shared by every CMDB importer
(serviceops_core/import_changes.py) and the import page that shows it."""
import json
from datetime import date

from app import ConfigurationItem, IntegrationSyncJob, PlatformSetting, User, db, now
from serviceops_core import import_changes
from serviceops_core.cmdb_import import import_ci_rows, parse_ci_rows
from serviceops_core.snipeit_sync import sync_from_snipeit
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)
from tests.test_snipeit_sync import FakeSnipeit, configure, factory, make_asset


def test_update_lists_only_real_changes_and_counts_unchanged_items(app):
    with app.app_context():
        ci = ConfigurationItem(name="web-01", ci_class="Server", vendor="Dell", model="R640",
                               install_date=date(2020, 1, 1), tenant_id=1, attributes={"a": 1})
        db.session.add(ci)
        db.session.flush()
        summary = {}
        before = import_changes.snapshot(ci)
        ci.model, ci.install_date, ci.attributes = "R650", date(2021, 5, 6), {"a": 2, "b": 3}
        import_changes.record_update(summary, before, ci)
        (change,) = summary["changes"]
        assert change["action"] == "update" and change["name"] == "web-01"
        fields = {field["label"]: field for field in change["fields"]}
        assert fields["Model"] == {"label": "Model", "before": "R640", "after": "R650"}
        assert fields["Install date"]["after"] == "2021-05-06"
        assert fields["Attributes"]["after"] == "2 source attributes changed"
        assert "Manufacturer" not in fields

        import_changes.record_update(summary, import_changes.snapshot(ci), ci)
        assert summary["cis_unchanged"] == 1 and summary["changes_total"] == 1


def test_change_list_is_capped_and_a_failed_record_leaves_no_trace(app):
    with app.app_context():
        summary = {}
        for number in range(import_changes.CHANGE_LIMIT + 5):
            import_changes.record_create(summary, ConfigurationItem(name=f"ci-{number}", ci_class="Server"))
        assert len(summary["changes"]) == import_changes.CHANGE_LIMIT
        assert summary["changes_total"] == import_changes.CHANGE_LIMIT + 5

        small = {}
        import_changes.record_create(small, ConfigurationItem(name="kept", ci_class="Server"))
        saved = import_changes.checkpoint(small)
        import_changes.record_create(small, ConfigurationItem(name="rolled-back", ci_class="Server"))
        import_changes.restore(small, saved)
        assert [change["name"] for change in small["changes"]] == ["kept"] and small["changes_total"] == 1


def test_owner_and_team_changes_show_names_not_ids(app):
    with app.app_context():
        user = User.query.filter_by(username="employee").one()
        ci = ConfigurationItem(name="lap-9", ci_class="Laptop", tenant_id=1)
        db.session.add(ci)
        db.session.flush()
        summary, before = {}, import_changes.snapshot(ci)
        ci.owner_id = user.id
        import_changes.record_update(summary, before, ci)
        assert summary["changes"][0]["fields"][0] == {"label": "Owner", "before": "—", "after": user.name}


def test_snipeit_preview_reports_planned_changes_and_rerun_is_up_to_date(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        assets = [make_asset(1, name="lap-1", serial="S1"), make_asset(2, name="lap-2", serial="S2")]
        preview = sync_from_snipeit(1, dry_run=True, session_factory=factory(FakeSnipeit(
            records={"/api/v1/hardware": assets})))
        assert preview["changes_total"] == 2 and {c["action"] for c in preview["changes"]} == {"create"}
        assert {"label": "Serial", "after": "S1"} in preview["changes"][0]["fields"]

        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": assets})))
        rerun = sync_from_snipeit(1, dry_run=True, session_factory=factory(FakeSnipeit(
            records={"/api/v1/hardware": assets})))
        assert rerun["cis_unchanged"] == 2 and rerun["changes_total"] == 0

        moved = [make_asset(1, name="lap-1", serial="S1", location="Branch office"), assets[1]]
        third = sync_from_snipeit(1, dry_run=True, session_factory=factory(FakeSnipeit(
            records={"/api/v1/hardware": moved})))
        assert third["cis_unchanged"] == 1 and third["changes_total"] == 1
        location = next(f for f in third["changes"][0]["fields"] if f["label"] == "Location")
        assert (location["before"], location["after"]) == ("HQ", "Branch office")


def test_spreadsheet_preview_lists_changes(app):
    with app.app_context():
        db.session.add(ConfigurationItem(name="db-01", ci_class="Server", cost_center="CC-1", tenant_id=1))
        db.session.commit()
        result = import_ci_rows(parse_ci_rows("Host,Cost Center\ndb-01,CC-2\nnew-01,CC-3\n"), 1, dry_run=True)
        actions = {change["name"]: change for change in result["changes"]}
        assert actions["new-01"]["action"] == "create"
        assert {"label": "Cost center", "before": "CC-1", "after": "CC-2"} in actions["db-01"]["fields"]


def test_spreadsheet_apply_needs_the_review_confirmation(client, app):
    login(client)
    csv_text = "Host,Cost Center\nunconfirmed-01,CC-7\n"
    page = client.post("/cmdb/import", data={"action": "apply", "csv_text": csv_text}).get_data(as_text=True)
    assert "Confirm that you reviewed the preview" in page
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="unconfirmed-01").count() == 0
    client.post("/cmdb/import", data={"action": "apply", "csv_text": csv_text, "confirm_reviewed": "1"})
    with app.app_context():
        assert ConfigurationItem.query.filter_by(name="unconfirmed-01").one().cost_center == "CC-7"


def test_import_page_shows_tabs_steps_metrics_and_planned_changes(client, app):
    with app.app_context():
        db.session.add(PlatformSetting(key="SNIPEIT_ENABLED", value="true", encrypted=False))
        actor = User.query.filter_by(username="admin").one()
        result = {"dry_run": True, "assets_seen": 2, "cis_created": 1, "cis_updated": 1, "cis_unchanged": 0,
                  "cis_matched_by_serial": 0, "cis_enriched_netbox": 0, "assignees_unmatched": 0,
                  "errors": [], "warnings": [], "changes_total": 2, "changes": [
                      {"action": "create", "name": "lap-<1>", "fields": [{"label": "Serial", "after": "S1"}]},
                      {"action": "update", "name": "lap-2", "fields": [
                          {"label": "Location", "before": "HQ", "after": "Branch"}]}]}
        db.session.add(IntegrationSyncJob(
            tenant_id=1, actor_user_id=actor.id, integration="snipeit", dry_run=True, status="Completed",
            phase="Completed", result_json=json.dumps(result), finished_at=now()))
        db.session.commit()
    login(client)
    page = client.get("/cmdb/import").get_data(as_text=True)
    assert 'aria-label="Import sources"' in page
    for anchor in ("#netbox-sync", "#snipeit-sync", "#spreadsheet-import"):
        assert f'href="{anchor}"' in page
    assert "Planned changes" in page and "lap-&lt;1&gt;" in page and "<del>HQ</del> → <span>Branch</span>" in page
    assert "<dt>Would be created</dt><dd>1</dd>" in page and "Preview valid until" in page
    assert page.count("data-submit-once") >= 4
