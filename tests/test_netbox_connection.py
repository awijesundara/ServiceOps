"""NetBox connection test, failure reporting and the preview-before-import gate.

A sync that could not read NetBox used to finish as "Completed" with its
errors hidden, and the page never showed a background job's result, so a
refused token or a preview run looked like a successful sync that found
nothing."""
import json
from datetime import timedelta

import pytest
import requests

from app import (ConfigurationItem, IntegrationSyncJob, PlatformSetting, User, db, now,
                 process_integration_sync_jobs)
from serviceops_core import netbox_sync
from serviceops_core.netbox_sync import NetboxSyncError, normalize_base_url, probe_netbox, sync_from_netbox
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)
from tests.test_netbox_sync import make_device


class Reply:
    def __init__(self, payload=None, status=200, not_json=False):
        self.payload, self.status_code, self.not_json, self.is_redirect = payload, status, not_json, False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        if self.not_json:
            raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        return self.payload


class FakeNetbox:
    """Answers each API path with a list of records, an HTTP status or an
    exception; `limit` is honoured so probes see counts, not whole lists."""

    def __init__(self, records=None, statuses=None, raises=None, status_payload=None, not_json=False):
        self.records, self.statuses, self.raises = records or {}, statuses or {}, raises
        self.status_payload = status_payload if status_payload is not None else {"netbox-version": "4.4.1"}
        self.not_json, self.verify, self.requested = not_json, True, []

    def get(self, url, params=None, timeout=None, allow_redirects=None):
        path = url[url.index("/api/"):]
        self.requested.append(path)
        if self.raises:
            raise self.raises
        if self.not_json:
            return Reply(not_json=True)
        if path in self.statuses:
            return Reply(status=self.statuses[path])
        if path == "/api/status/":
            return Reply(self.status_payload)
        rows = self.records.get(path, [])
        limit = (params or {}).get("limit", len(rows) or 1)
        return Reply({"count": len(rows), "next": None, "results": rows[:limit]})

    def close(self):
        pass


def configure(monkeypatch, url="https://netbox.example.com"):
    for key, value in (("NETBOX_ENABLED", "true"), ("NETBOX_BASE_URL", url), ("NETBOX_API_TOKEN", "test-token")):
        row = db.session.get(PlatformSetting, key) or PlatformSetting(key=key)
        row.value, row.encrypted = value, False
        db.session.add(row)
    db.session.commit()
    import app as core_app
    monkeypatch.setattr(core_app, "integration_endpoint_resolves_safely", lambda url, **kwargs: True)


def inventory():
    device = make_device(7, "core-sw-01", serial="SN7", role="Core Switch", rack_id=3)
    device["rack"]["name"] = "R1"
    device["custom_fields"] = {}
    return {
        "/api/dcim/sites/": [{"id": 1, "name": "CC1"}],
        "/api/dcim/racks/": [{"id": 3, "name": "R1", "site": {"name": "CC1"}, "u_height": 42}],
        "/api/dcim/devices/": [device],
        "/api/dcim/device-roles/": [{"name": "Core Switch", "slug": "core-switch", "device_count": 1},
                                    {"name": "Hypervisor", "slug": "hypervisor", "device_count": 0}],
    }


def test_base_url_accepts_the_api_root_and_trailing_slashes():
    assert normalize_base_url(" https://netbox.example.com/api/ ") == "https://netbox.example.com"
    assert normalize_base_url("https://netbox.example.com/") == "https://netbox.example.com"
    assert normalize_base_url("https://example.com/netbox") == "https://example.com/netbox"


def test_connection_test_reports_version_counts_role_classes_and_a_sample(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch, url="https://netbox.example.com/api/")
        fake = FakeNetbox(records=inventory(), statuses={"/api/dcim/inventory-items/": 403})
        report = probe_netbox(1, session_factory=lambda base, token: fake)
        assert report["netbox_version"] == "4.4.1"
        assert report["base_url"] == "https://netbox.example.com"
        counts = {row["key"]: (row["count"], row["readable"]) for row in report["endpoints"]}
        assert counts["devices"] == (1, True) and counts["racks"] == (1, True)
        assert counts["inventory_items"] == (None, False)
        assert {role["name"]: role["ci_class"] for role in report["roles"]} == {
            "Core Switch": "Switch", "Hypervisor": "Server"}
        assert report["sample"][0]["name"] == "core-sw-01" and report["sample"][0]["rack"] == "R1"
        assert any("environment" in warning for warning in report["warnings"])
        assert report["ready"] is True
        assert "/api/api/" not in "".join(fake.requested)
        assert ConfigurationItem.query.count() == 0


@pytest.mark.parametrize("fake, expected", [
    (FakeNetbox(raises=requests.exceptions.SSLError("bad cert")), "certificate is not trusted"),
    (FakeNetbox(raises=requests.exceptions.ConnectionError("refused")), "could not be reached"),
    (FakeNetbox(not_json=True), "something other than the NetBox API"),
    (FakeNetbox(statuses={"/api/status/": 404}), "No NetBox API was found"),
    (FakeNetbox(status_payload={"hello": "world"}), "not as a NetBox API"),
    (FakeNetbox(statuses={path: 403 for _key, _label, path, _required in netbox_sync.PROBE_ENDPOINTS}),
     "refused every inventory read"),
])
def test_connection_test_explains_why_it_failed(app, monkeypatch, fake, expected):
    with app.app_context():
        configure(monkeypatch)
        with pytest.raises(NetboxSyncError, match=expected) as raised:
            probe_netbox(1, session_factory=lambda base, token: fake)
        assert "test-token" not in str(raised.value)


def test_connection_test_warns_when_the_token_can_see_nothing(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        report = probe_netbox(1, session_factory=lambda base, token: FakeNetbox(
            statuses={"/api/dcim/devices/": 403}))
        assert report["ready"] is False
        assert any("cannot read: Physical devices" in warning for warning in report["warnings"])
        assert any("sees no racks, devices or virtual machines" in warning for warning in report["warnings"])


def test_a_refused_token_fails_the_sync_instead_of_completing_empty(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        fake = FakeNetbox(statuses={"/api/dcim/racks/": 403})
        with pytest.raises(NetboxSyncError, match="Nothing was imported. NetBox refused the API token"):
            sync_from_netbox(1, session_factory=lambda base, token: fake)


def test_component_types_missing_from_this_netbox_version_are_skipped_quietly(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        fake = FakeNetbox(records={"/api/dcim/devices/": [make_device(1, "srv-01")]},
                          statuses={"/api/dcim/cooling-intakes/": 404, "/api/dcim/cooling-outflows/": 404,
                                    "/api/dcim/modules/": 403})
        result = sync_from_netbox(1, dry_run=True, session_factory=lambda base, token: fake)
        assert result["devices_seen"] == 1
        assert result["warnings"] == [
            "Modules were not imported: the token is not permitted to read them."]


def test_an_empty_result_carries_an_explanation(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        result = sync_from_netbox(1, dry_run=True, session_factory=lambda base, token: FakeNetbox())
        assert any("object permissions hide them" in warning for warning in result["warnings"])


def test_worker_marks_a_netbox_failure_failed_with_the_plain_reason(app, monkeypatch):
    with app.app_context():
        actor = User.query.filter_by(username="admin").one()
        job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration="netbox", dry_run=True)
        db.session.add(job)
        db.session.commit()

        def refused(*_args, **_kwargs):
            raise NetboxSyncError("Nothing was imported. NetBox refused the API token (HTTP 403).")

        monkeypatch.setattr("serviceops_core.netbox_sync.sync_from_netbox", refused)
        assert process_integration_sync_jobs() == 1
        failed = db.session.get(IntegrationSyncJob, job.id)
        assert failed.status == "Failed"
        assert failed.error == "Nothing was imported. NetBox refused the API token (HTTP 403)."


def finished_job(dry_run=True, result=None, age=timedelta(minutes=5), status="Completed"):
    actor = User.query.filter_by(username="admin").one()
    result = result if result is not None else {
        "dry_run": dry_run, "devices_seen": 3, "virtual_machines_seen": 1, "cis_created": 2, "cis_updated": 2,
        "cis_matched_by_serial": 1, "racks_created": 1, "racks_updated": 0,
        "errors": [], "warnings": ["Inventory Items were not imported: HTTPError"]}
    job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration="netbox", dry_run=dry_run,
                             status=status, phase=status, result_json=json.dumps(result),
                             created_at=now() - age, finished_at=now() - age)
    db.session.add(job)
    db.session.commit()
    return job.id


def enable(app):
    with app.app_context():
        db.session.add(PlatformSetting(key="NETBOX_ENABLED", value="true", encrypted=False))
        db.session.commit()


def queued_imports(app):
    with app.app_context():
        return IntegrationSyncJob.query.filter_by(dry_run=False, status="Pending").count()


def test_page_shows_the_finished_jobs_counts_errors_and_warnings(client, app):
    enable(app)
    login(client)
    with app.app_context():
        finished_job()
    page = client.get("/cmdb/import").get_data(as_text=True)
    assert "<dt>Devices</dt><dd>3</dd>" in page and "<dt>Would be created</dt><dd>2</dd>" in page
    assert "Inventory Items were not imported" in page
    assert "This was a preview: nothing was saved." in page
    assert "Import into CMDB" in page


def test_import_is_refused_without_a_fresh_clean_preview(client, app):
    enable(app)
    login(client)
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    with app.app_context():
        finished_job(age=timedelta(hours=25))
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    with app.app_context():
        finished_job(result={"devices_seen": 2, "errors": ["device x: KeyError"], "warnings": []})
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    with app.app_context():
        finished_job(result={"devices_seen": 0, "virtual_machines_seen": 0, "racks_created": 0,
                             "racks_updated": 0, "errors": [], "warnings": []})
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0


def test_import_needs_the_review_confirmation_and_consumes_the_preview(client, app):
    enable(app)
    login(client)
    with app.app_context():
        finished_job()
    client.post("/cmdb/import/netbox", data={})
    assert queued_imports(app) == 0
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 1
    with app.app_context():
        job = IntegrationSyncJob.query.filter_by(dry_run=False).one()
        job.status, job.finished_at = "Completed", now()
        db.session.commit()
    client.post("/cmdb/import/netbox", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    assert "Import into CMDB" not in client.get("/cmdb/import").get_data(as_text=True)


def test_connection_test_page_renders_the_report_and_is_admin_only(client, app, monkeypatch):
    enable(app)
    report = {"base_url": "https://netbox.example.com", "token_type": "v1 (Token)", "netbox_version": "4.4.1",
              "endpoints": [{"key": "devices", "label": "Physical devices", "required": True, "count": 12,
                             "readable": True}],
              "roles": [{"name": "Core Switch", "devices": 4, "ci_class": "Switch"}],
              "sample": [], "warnings": [], "cmdb_total": 0, "cmdb_from_netbox": 0, "ready": True}
    monkeypatch.setattr(netbox_sync, "probe_netbox", lambda tenant_id: report)
    login(client, "employee", "Employee123!")
    assert client.post("/cmdb/import/netbox/test").status_code in (302, 403)
    client.get("/logout")
    login(client)
    page = client.post("/cmdb/import/netbox/test").get_data(as_text=True)
    assert "Connected to NetBox 4.4.1" in page and "Core Switch (4) → Switch" in page

    def refused(tenant_id):
        raise NetboxSyncError("NetBox refused the API token (HTTP 403).")

    monkeypatch.setattr(netbox_sync, "probe_netbox", refused)
    assert "Connection failed." in client.post("/cmdb/import/netbox/test").get_data(as_text=True)
