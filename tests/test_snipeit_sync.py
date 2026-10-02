"""Snipe-IT asset inventory sync (serviceops_core/snipeit_sync.py).

Snipe-IT is mocked entirely by a fake session, the same approach as the
NetBox tests."""
import json
from datetime import date, timedelta

import pytest
import requests

from app import (ConfigurationItem, IntegrationSyncJob, PlatformSetting, User, db, now,
                 process_integration_sync_jobs)
from serviceops_core import snipeit_sync
from serviceops_core.cmdb_import import import_ci_rows, parse_ci_rows
from serviceops_core.snipeit_sync import (SnipeitSyncError, _snipeit_session, category_class, map_asset,
                                          normalize_base_url, probe_snipeit, sync_from_snipeit)
from tests.test_app import app, client, login  # noqa: F401  (pytest fixtures)


class Reply:
    def __init__(self, payload=None, status=200, not_json=False, redirect=False):
        self.payload, self.status_code, self.not_json, self.is_redirect = payload, status, not_json, redirect

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        if self.not_json:
            raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        return self.payload


class FakeSnipeit:
    """Answers each /api/v1 path with rows, honouring limit/offset so paging
    is exercised; `statuses` forces an HTTP status for a path."""

    def __init__(self, records=None, statuses=None, raises=None, not_json=False, me=None, error_envelope=None):
        self.records, self.statuses, self.raises = records or {}, statuses or {}, raises
        self.not_json, self.error_envelope = not_json, error_envelope
        self.me = me if me is not None else {"id": 9, "name": "Inventory Reader", "username": "reader"}
        self.verify, self.requested = True, []

    def get(self, url, params=None, timeout=None, allow_redirects=None):
        path = url[url.index("/api/"):]
        self.requested.append((path, dict(params or {})))
        if self.raises:
            raise self.raises
        if self.not_json:
            return Reply(not_json=True)
        if path in self.statuses:
            return Reply(status=self.statuses[path])
        if self.error_envelope and path == self.error_envelope:
            return Reply({"status": "error", "messages": "Unauthorized &amp; denied"})
        if path == "/api/v1/users/me":
            return Reply(self.me)
        rows = self.records.get(path, [])
        offset, limit = int((params or {}).get("offset", 0)), int((params or {}).get("limit", 500))
        return Reply({"total": len(rows), "rows": rows[offset:offset + limit]})

    def close(self):
        pass


def make_asset(asset_id, name="MacBook Pro", tag=None, serial=None, category="Laptops", meta="deployed",
               assigned_email=None, custom_fields=None, location="HQ", purchase="2024-02-01",
               warranty="2027-02-01"):
    return {
        "id": asset_id, "name": name, "asset_tag": tag or f"A-{asset_id:04d}", "serial": serial,
        "model": {"id": 1, "name": "MacBook Pro 14"}, "model_number": "MX2H3",
        "manufacturer": {"id": 1, "name": "Apple"}, "category": {"id": 2, "name": category},
        "status_label": {"id": 1, "name": "Deployed" if meta == "deployed" else meta.title(),
                         "status_type": "deployable", "status_meta": meta},
        "company": {"id": 1, "name": "R&amp;D Ltd"}, "supplier": {"id": 3, "name": "Reseller"},
        "location": {"id": 4, "name": location} if location else None,
        "rtd_location": {"id": 5, "name": "Store room"},
        "assigned_to": ({"id": 11, "type": "user", "name": "Jane Doe", "username": "jdoe", "email": assigned_email}
                        if assigned_email else None),
        "purchase_date": {"date": purchase, "formatted": purchase} if purchase else None,
        "warranty_expires": {"date": warranty, "formatted": warranty} if warranty else None,
        "warranty_months": "36 months", "purchase_cost": "2,499.00", "order_number": "PO-77",
        "notes": "Has a &quot;dent&quot;", "custom_fields": custom_fields or {},
        "created_at": {"datetime": "2024-02-02 10:00:00", "formatted": "..."},
        "updated_at": {"datetime": "2024-06-02 10:00:00", "formatted": "..."},
    }


def configure(monkeypatch, url="https://snipeit.example.com"):
    for key, value in (("SNIPEIT_ENABLED", "true"), ("SNIPEIT_BASE_URL", url), ("SNIPEIT_API_TOKEN", "snipe-token")):
        row = db.session.get(PlatformSetting, key) or PlatformSetting(key=key)
        row.value, row.encrypted = value, False
        db.session.add(row)
    db.session.commit()
    import app as core_app
    monkeypatch.setattr(core_app, "integration_endpoint_resolves_safely", lambda url, **kwargs: True)


def factory(fake):
    return lambda base_url, token: fake


def test_base_url_accepts_the_api_root_and_trailing_slashes():
    assert normalize_base_url(" https://snipeit.example.com/api/v1/ ") == "https://snipeit.example.com"
    assert normalize_base_url("https://snipeit.example.com/api") == "https://snipeit.example.com"
    assert normalize_base_url("https://example.com/assets/") == "https://example.com/assets"


@pytest.mark.parametrize("category, ci_class", [
    ("Laptops", "Laptop"), ("Desktop PCs", "Desktop"), ("Rack Servers", "Server"), ("Monitors", "Monitor"),
    ("Mobile Phones", "Mobile Device"), ("Wireless Access Points", "Wireless Access Point"),
    ("Network Switches", "Switch"), ("Automobiles", "Hardware Asset"), (None, "Hardware Asset"),
])
def test_categories_map_to_controlled_ci_classes(category, ci_class):
    assert category_class(category) == ci_class


def test_asset_mapping_unescapes_text_and_keeps_snipeit_data_as_attributes():
    mapped = map_asset(make_asset(42, serial="C02X", custom_fields={
        "IP Address": {"field": "_snipeit_ip_1", "value": "10.0.0.5", "field_format": "IP"},
        "RAM": {"field": "_snipeit_ram_2", "value": "32 GB", "field_format": "ANY"},
    }), "https://snipeit.example.com")
    assert mapped["name"] == "MacBook Pro" and mapped["ci_class"] == "Laptop"
    assert (mapped["vendor"], mapped["model"], mapped["serial_number"]) == ("Apple", "MacBook Pro 14", "C02X")
    assert mapped["ip_address"] == "10.0.0.5" and mapped["location"] == "HQ"
    assert mapped["install_date"] == date(2024, 2, 1) and mapped["warranty_expiry_date"] == date(2027, 2, 1)
    assert (mapped["operational_status"], mapped["lifecycle_state"]) == ("Operational", "In Use")
    attributes = mapped["attributes"]
    assert attributes["Snipe-IT: Company"] == "R&D Ltd"
    assert attributes["Snipe-IT: Notes"] == 'Has a "dent"'
    assert attributes["Snipe-IT: RAM"] == "32 GB"
    assert attributes["Snipe-IT: Record"] == "https://snipeit.example.com/hardware/42"
    assert mapped["external_id"] == "hardware:42"


def test_status_meta_drives_lifecycle_and_unnamed_assets_use_the_tag():
    archived = map_asset(make_asset(1, name="", tag="T-1", meta="archived", location=None))
    assert archived["name"] == "T-1"
    assert (archived["operational_status"], archived["lifecycle_state"]) == ("Retired", "Retired")
    assert archived["location"] == "Store room"
    assert map_asset(make_asset(2, meta="deployable"))["lifecycle_state"] == "Planned"
    assert map_asset(make_asset(3, meta="undeployable"))["operational_status"] == "Down"


def test_session_uses_bearer_json_and_the_snipeit_proxy_policy(app):
    with app.app_context():
        db.session.add(PlatformSetting(key="OUTBOUND_PROXY_URL", value="http://default:3128", encrypted=False))
        db.session.add(PlatformSetting(key="SNIPEIT_PROXY_MODE", value="none", encrypted=False))
        db.session.commit()
        session = _snipeit_session("https://snipeit.example.com", "tok")
        assert session.headers["Authorization"] == "Bearer tok"
        assert session.headers["Accept"] == "application/json"
        assert "https" not in session.proxies and session.trust_env is False


def test_sync_creates_pages_through_and_reruns_idempotently(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        assets = [make_asset(i, name=f"laptop-{i}", serial=f"SN{i}") for i in range(1, 26)]
        fake = FakeSnipeit(records={"/api/v1/hardware": assets})
        result = sync_from_snipeit(1, session_factory=factory(fake), page_size=10)
        assert result["assets_seen"] == 25 and result["cis_created"] == 25 and not result["errors"]
        offsets = [params["offset"] for path, params in fake.requested if path == "/api/v1/hardware"]
        assert offsets == [0, 10, 20]
        assert all(params.get("sort") == "id" for path, params in fake.requested if path == "/api/v1/hardware")
        ci = ConfigurationItem.query.filter_by(name="laptop-3").one()
        assert (ci.external_source, ci.external_id, ci.ci_class) == ("snipeit", "hardware:3", "Laptop")
        assert ci.attributes["Snipe-IT: Asset Tag"] == "A-0003"

        again = sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": assets})))
        assert again["cis_created"] == 0 and again["cis_updated"] == 25
        assert ConfigurationItem.query.filter_by(external_source="snipeit").count() == 25


def test_preview_writes_nothing(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        fake = FakeSnipeit(records={"/api/v1/hardware": [make_asset(1), make_asset(2)]})
        result = sync_from_snipeit(1, dry_run=True, session_factory=factory(fake))
        assert result["cis_created"] == 2 and result["dry_run"] is True
        assert ConfigurationItem.query.filter_by(external_source="snipeit").count() == 0


def test_assets_sharing_a_generic_name_stay_separate(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        assets = [make_asset(1, name="MacBook Pro", tag="A-1"), make_asset(2, name="MacBook Pro", tag="A-2")]
        for _ in range(2):
            sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": assets})))
        names = sorted(ci.name for ci in ConfigurationItem.query.filter_by(external_source="snipeit"))
        assert names == ["MacBook Pro", "MacBook Pro (A-2)"]


def test_checked_out_asset_gets_the_matching_user_as_owner_and_loses_it_on_return(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        user = User.query.filter_by(username="employee").one()
        assets = [make_asset(1, assigned_email=user.email.upper()), make_asset(2, name="spare",
                                                                              assigned_email="ghost@nowhere.test")]
        result = sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": assets})))
        assert result["assignees_unmatched"] == 1
        assert any("no ServiceOps account" in warning for warning in result["warnings"])
        ci = ConfigurationItem.query.filter_by(external_id="hardware:1").one()
        assert ci.owner_id == user.id
        assert ci.attributes["Snipe-IT: Assigned To"] == "Jane Doe"

        returned = [make_asset(1, meta="deployable")]
        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": returned})))
        ci = ConfigurationItem.query.filter_by(external_id="hardware:1").one()
        assert ci.owner_id is None and ci.lifecycle_state == "Planned"
        assert "Snipe-IT: Assigned To" not in ci.attributes


def test_netbox_items_keep_netbox_hardware_and_only_gain_asset_data(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        db.session.add(ConfigurationItem(
            name="db-01", ci_class="Server", serial_number="SRV1", vendor="Dell", model="R750",
            location="DC1 / Row A", operational_status="Down", lifecycle_state="In Use",
            external_source="netbox", external_id="dcim.device:5", tenant_id=1,
            attributes={"NetBox: Role": "Database", "Manual note": "keep"}))
        db.session.commit()
        asset = make_asset(9, name="Database server", serial="SRV1", category="Servers", location="Somewhere")
        result = sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={"/api/v1/hardware": [asset]})))
        assert result["cis_matched_by_serial"] == 1 and result["cis_enriched_netbox"] == 1
        ci = ConfigurationItem.query.filter_by(serial_number="SRV1").one()
        assert (ci.name, ci.vendor, ci.model, ci.location) == ("db-01", "Dell", "R750", "DC1 / Row A")
        assert (ci.external_source, ci.operational_status) == ("netbox", "Down")
        assert ci.install_date == date(2024, 2, 1) and ci.warranty_expiry_date == date(2027, 2, 1)
        assert ci.attributes["NetBox: Role"] == "Database" and ci.attributes["Manual note"] == "keep"
        assert ci.attributes["Snipe-IT: Asset ID"] == "9"


def test_one_bad_record_is_isolated(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        broken = make_asset(2)
        broken["purchase_date"] = {"date": "2024-13-45"}
        broken["model"] = "not-a-dict"
        broken.pop("id")
        broken["id"] = None
        result = sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
            "/api/v1/hardware": [make_asset(1), broken, make_asset(3, name="other")]})))
        assert result["cis_created"] == 2 and len(result["errors"]) == 1


@pytest.mark.parametrize("fake, expected", [
    (FakeSnipeit(raises=requests.exceptions.SSLError("bad cert")), "certificate is not trusted"),
    (FakeSnipeit(raises=requests.exceptions.ConnectionError("refused")), "could not be reached"),
    (FakeSnipeit(not_json=True), "something other than the Snipe-IT API"),
    (FakeSnipeit(statuses={"/api/v1/users/me": 401}), "refused the API token"),
    (FakeSnipeit(statuses={"/api/v1/hardware": 403}), "cannot list hardware assets"),
])
def test_connection_test_explains_why_it_failed(app, monkeypatch, fake, expected):
    with app.app_context():
        configure(monkeypatch)
        with pytest.raises(SnipeitSyncError, match=expected) as raised:
            probe_snipeit(1, session_factory=factory(fake))
        assert "snipe-token" not in str(raised.value)


def test_connection_test_reports_user_counts_classes_and_sample(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch, url="https://snipeit.example.com/api/v1/")
        fake = FakeSnipeit(records={
            "/api/v1/hardware": [make_asset(1, assigned_email="ghost@nowhere.test")],
            "/api/v1/categories": [{"id": 2, "name": "Laptops", "assets_count": 1}],
            "/api/v1/statuslabels": [{"id": 1, "name": "Broken", "type": "undeployable"}],
        }, statuses={"/api/v1/locations": 403})
        report = probe_snipeit(1, session_factory=factory(fake))
        assert report["base_url"] == "https://snipeit.example.com" and report["token_user"] == "Inventory Reader"
        counts = {row["key"]: (row["count"], row["readable"]) for row in report["endpoints"]}
        assert counts["assets"] == (1, True) and counts["locations"] == (None, False)
        assert report["categories"] == [{"name": "Laptops", "assets": 1, "ci_class": "Laptop"}]
        assert report["status_labels"][0]["lifecycle_state"] == "Maintenance"
        assert report["sample"][0]["owner_matched"] is False
        assert any("no ServiceOps account" in warning for warning in report["warnings"])
        assert report["ready"] is True and ConfigurationItem.query.count() == 0


def test_a_failed_request_fails_the_sync_and_writes_nothing(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        with pytest.raises(SnipeitSyncError, match="Nothing was imported"):
            sync_from_snipeit(1, session_factory=factory(FakeSnipeit(statuses={"/api/v1/hardware": 401})))
        with pytest.raises(SnipeitSyncError, match="Unauthorized & denied"):
            sync_from_snipeit(1, session_factory=factory(FakeSnipeit(error_envelope="/api/v1/hardware")))
        assert ConfigurationItem.query.filter_by(external_source="snipeit").count() == 0


def test_sync_refuses_when_disabled_or_unsafe(app, monkeypatch):
    with app.app_context():
        with pytest.raises(SnipeitSyncError, match="not enabled"):
            sync_from_snipeit(1, session_factory=factory(FakeSnipeit()))
        configure(monkeypatch, url="http://snipeit.example.com")
        with pytest.raises(SnipeitSyncError, match="safety validation"):
            sync_from_snipeit(1, session_factory=factory(FakeSnipeit()))


def test_spreadsheet_import_leaves_snipeit_owned_fields_alone(app, monkeypatch):
    with app.app_context():
        configure(monkeypatch)
        sync_from_snipeit(1, session_factory=factory(FakeSnipeit(records={
            "/api/v1/hardware": [make_asset(1, name="lap-1", serial="S1")]})))
        result = import_ci_rows(parse_ci_rows("Host,Serial Number,Vendor,Cost Center\nlap-1,S1,Other,CC-9\n"),
                                1, dry_run=False)
        assert result["fields_skipped_snipeit_owned"] >= 1
        ci = ConfigurationItem.query.filter_by(name="lap-1").one()
        assert ci.vendor == "Apple" and ci.cost_center == "CC-9"


def test_worker_runs_snipeit_jobs_and_reports_failures_plainly(app, monkeypatch):
    with app.app_context():
        actor = User.query.filter_by(username="admin").one()
        job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration="snipeit", dry_run=True)
        db.session.add(job)
        db.session.commit()

        def refused(*_args, **_kwargs):
            raise SnipeitSyncError("Nothing was imported. Snipe-IT refused the API token (HTTP 401).")

        monkeypatch.setattr("serviceops_core.snipeit_sync.sync_from_snipeit", refused)
        assert process_integration_sync_jobs() == 1
        failed = db.session.get(IntegrationSyncJob, job.id)
        assert failed.status == "Failed" and failed.error.startswith("Nothing was imported. Snipe-IT refused")

        job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration="snipeit", dry_run=True)
        db.session.add(job)
        db.session.commit()
        monkeypatch.setattr("serviceops_core.snipeit_sync.sync_from_snipeit",
                            lambda *args, **kwargs: {"assets_seen": 4, "errors": [], "warnings": []})
        assert process_integration_sync_jobs() == 1
        assert db.session.get(IntegrationSyncJob, job.id).status == "Completed"


def finished_preview(result=None, age=timedelta(minutes=5)):
    actor = User.query.filter_by(username="admin").one()
    result = result if result is not None else {
        "dry_run": True, "assets_seen": 4, "cis_created": 3, "cis_updated": 1, "cis_matched_by_serial": 1,
        "cis_enriched_netbox": 0, "assignees_unmatched": 0, "errors": [], "warnings": []}
    job = IntegrationSyncJob(tenant_id=1, actor_user_id=actor.id, integration="snipeit", dry_run=True,
                             status="Completed", phase="Completed", result_json=json.dumps(result),
                             created_at=now() - age, finished_at=now() - age)
    db.session.add(job)
    db.session.commit()


def queued_imports(app):
    with app.app_context():
        return IntegrationSyncJob.query.filter_by(integration="snipeit", dry_run=False, status="Pending").count()


def test_page_preview_gate_and_admin_only_routes(client, app, monkeypatch):
    with app.app_context():
        db.session.add(PlatformSetting(key="SNIPEIT_ENABLED", value="true", encrypted=False))
        db.session.commit()
    login(client, "employee", "Employee123!")
    assert client.post("/cmdb/import/snipeit/test").status_code in (302, 403)
    assert client.post("/cmdb/import/snipeit", data={"dry_run": "1"}).status_code in (302, 403)
    client.get("/logout")
    login(client)
    page = client.get("/cmdb/import").get_data(as_text=True)
    assert "Sync from Snipe-IT" in page and "Available after a successful preview that found assets" in page

    client.post("/cmdb/import/snipeit", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    with app.app_context():
        finished_preview(result={"assets_seen": 0, "errors": [], "warnings": []})
    client.post("/cmdb/import/snipeit", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 0
    with app.app_context():
        finished_preview()
    page = client.get("/cmdb/import").get_data(as_text=True)
    assert "found <strong>4 assets</strong>" in page
    client.post("/cmdb/import/snipeit", data={})
    assert queued_imports(app) == 0
    client.post("/cmdb/import/snipeit", data={"confirm_reviewed": "1"})
    assert queued_imports(app) == 1

    with app.app_context():
        job = IntegrationSyncJob.query.filter_by(integration="snipeit", dry_run=False).one()
        job_id = job.id
    status = client.get(f"/cmdb/import/snipeit/jobs/{job_id}").get_json()
    assert status["status"] == "Pending"
    assert client.get(f"/cmdb/import/netbox/jobs/{job_id}").status_code == 404
    assert client.post(f"/cmdb/import/snipeit/jobs/{job_id}/cancel").get_json()["status"] == "Cancelled"


def test_connection_test_page_renders_the_report(client, app, monkeypatch):
    with app.app_context():
        db.session.add(PlatformSetting(key="SNIPEIT_ENABLED", value="true", encrypted=False))
        db.session.commit()
    report = {"base_url": "https://snipeit.example.com", "token_user": "Inventory Reader", "egress": "a direct connection",
              "endpoints": [{"key": "assets", "label": "Hardware assets", "required": True, "count": 12,
                             "readable": True}],
              "categories": [{"name": "Laptops", "assets": 12, "ci_class": "Laptop"}],
              "status_labels": [], "sample": [], "warnings": [], "cmdb_total": 0, "cmdb_from_snipeit": 0,
              "ready": True}
    monkeypatch.setattr(snipeit_sync, "probe_snipeit", lambda tenant_id: report)
    login(client)
    page = client.post("/cmdb/import/snipeit/test").get_data(as_text=True)
    assert "Connected to Snipe-IT" in page and "as Inventory Reader" in page and "Laptops (12) → Laptop" in page

    def refused(tenant_id):
        raise SnipeitSyncError("Snipe-IT refused the API token (HTTP 401).")

    monkeypatch.setattr(snipeit_sync, "probe_snipeit", refused)
    assert "Connection failed." in client.post("/cmdb/import/snipeit/test").get_data(as_text=True)


def test_settings_page_offers_the_connection_and_proxy_choice(client):
    login(client)
    page = client.get("/admin/settings/snipeit_connection").get_data(as_text=True)
    assert "Snipe-IT base URL" in page and 'name="SNIPEIT_PROXY_MODE"' in page and "Test connection" in page
