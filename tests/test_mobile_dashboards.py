"""B-464 on mobile: dashboards as JSON, and the ticket list behind each number."""
import json

from app import APIClient, Dashboard, MOBILE_API_SCOPES, Tenant, User, create_api_token, db
from serviceops_core import dashboards as boards
from tests.test_app import app, client, login  # noqa: F401
from tests.test_dashboards import _database_member, _reconcile_world, _team_dashboard

MOBILE_HEADERS = {"X-ServiceOps-Platform": "iOS", "X-ServiceOps-App-Version": "1.4.0",
                  "X-ServiceOps-App-Build": "10", "X-ServiceOps-Device": "iPhone17,1"}


def _mobile_session(client, username, password):
    response = client.post("/api/v1/auth/mobile/login", json={"username": username, "password": password},
                           headers=MOBILE_HEADERS)
    assert response.status_code == 200, response.json
    return response.json


def _bearer(session):
    return {"Authorization": f"Bearer {session['access_token']}"}


def _list_total(client, headers, reference):
    response = client.get("/api/v1/mobile/ticket-list", headers=headers, query_string={
        "kind": reference["kind"], "filter": json.dumps(reference["filter"]), "limit": 100})
    assert response.status_code == 200, response.json
    assert len(response.json["data"]) == min(response.json["meta"]["total"], 100)
    return response.json["meta"]["total"]


def test_every_mobile_dashboard_number_opens_a_list_of_that_many_tickets(client, app):
    group_id = _reconcile_world(app)
    login(client, "database.manager", "Manager123!")
    team_id = _team_dashboard(client, group_id)
    client.post("/logout")
    headers = _bearer(_mobile_session(client, "db.member", "DbMember123!"))

    listing = client.get("/api/v1/mobile/dashboards", headers=headers).json["data"]
    ids = [row["id"] for row in listing["dashboards"]]
    assert team_id in ids and listing["home_id"] in ids
    with app.app_context(), app.test_request_context("/"):
        member = User.query.filter_by(username="db.member").one()
        personal = db.session.get(Dashboard, listing["home_id"])
        for key in ("ticket_chart", "team_workload", "note"):
            boards.add_widget(member, personal, key)
        db.session.commit()

    checked = 0
    for dashboard_id in (listing["home_id"], team_id):
        document = client.get(f"/api/v1/mobile/dashboards/{dashboard_id}", headers=headers).json["data"]
        assert document["editable"] is (dashboard_id != team_id)
        for widget in document["widgets"]:
            assert widget["view"] != "unsupported", widget["key"]
            numbered = [(tile["count"], tile["list"]) for tile in widget.get("tiles", [])]
            numbered += [(bar["count"], bar["list"]) for bar in widget.get("bars", []) if bar["list"]]
            numbered += [(row["tickets"], row["list"]) for row in widget.get("members", [])]
            if widget["view"] == "bars":
                numbered.append((widget["total"], widget["list"]))
            for count, reference in numbered:
                assert _list_total(client, headers, reference) == count, (widget["key"], reference)
                checked += 1
            if widget["view"] == "tickets":
                assert _list_total(client, headers, widget["list"]) >= len(widget["tickets"])
                checked += 1
    assert checked > 10


def test_mobile_dashboards_keep_membership_tenant_and_session_boundaries(client, app):
    group_id, _ = _database_member(app)
    login(client, "database.manager", "Manager123!")
    team_id = _team_dashboard(client, group_id)
    client.post("/logout")
    with app.app_context():
        other = Tenant(slug="mobile-dash-other", name="Other")
        db.session.add(other)
        db.session.flush()
        foreign = Dashboard(tenant_id=other.id, scope="personal", name="Foreign", description="", position=0)
        db.session.add(foreign)
        db.session.commit()
        foreign_id = foreign.id

    employee = _bearer(_mobile_session(client, "employee", "Employee123!"))
    assert client.get(f"/api/v1/mobile/dashboards/{team_id}", headers=employee).status_code == 404
    assert client.get(f"/api/v1/mobile/dashboards/{foreign_id}", headers=employee).status_code == 404
    assert team_id not in [row["id"] for row in
                           client.get("/api/v1/mobile/dashboards", headers=employee).json["data"]["dashboards"]]
    assert client.get("/api/v1/mobile/ticket-list?kind=problem", headers=employee).status_code == 400
    assert client.get("/api/v1/mobile/ticket-list?filter=%7Bnope", headers=employee).status_code == 400

    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        token, prefix, hashed = create_api_token()
        db.session.add(APIClient(name="Integration", token_prefix=prefix, token_hash=hashed,
                                 scopes_json=json.dumps(["tickets:read"]), acting_user_id=admin.id,
                                 created_by_id=admin.id, tenant_id=admin.tenant_id))
        db.session.commit()
    integration = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/mobile/dashboards", headers=integration).status_code == 403
    assert client.get("/api/v1/mobile/ticket-list", headers=integration).status_code == 403


def test_a_refresh_brings_an_older_mobile_session_up_to_the_current_scopes(client, app):
    session = _mobile_session(client, "admin", "Admin123!")
    with app.app_context():
        row = APIClient.query.filter_by(client_kind="mobile").order_by(APIClient.id.desc()).first()
        row.scopes_json = json.dumps(["tickets:read"])
        db.session.commit()
    refreshed = client.post("/api/v1/auth/mobile/refresh", json={"refresh_token": session["refresh_token"]},
                            headers=MOBILE_HEADERS)
    assert refreshed.status_code == 200, refreshed.json
    with app.app_context():
        row = APIClient.query.filter_by(client_kind="mobile").order_by(APIClient.id.desc()).first()
        assert set(json.loads(row.scopes_json)) == MOBILE_API_SCOPES
    assert client.get("/api/v1/projects", headers=_bearer(refreshed.json)).status_code in (200, 404)
