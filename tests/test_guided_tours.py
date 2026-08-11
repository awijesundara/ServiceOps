"""Tests for B-120 guided tours: admin authoring, tenant isolation,
role/route targeting, and version-bump re-prompting.
"""
from app import GuidedTour, GuidedTourStep, Tenant, User, UserTourProgress, db
from tests.test_app import app, client, login


def _create_tour_with_step(app, target_route="dashboard", target_roles=""):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        tour = GuidedTour(
            tenant_id=1, key="dashboard-intro", title="Dashboard tour",
            description="Intro", target_route=target_route, target_roles=target_roles,
            created_by_id=admin_id,
        )
        db.session.add(tour)
        db.session.flush()
        db.session.add(GuidedTourStep(
            tenant_id=1, tour_id=tour.id, step_order=1,
            target_selector="[data-tour='dashboard-stats']", title="Your stats",
            body="Here's what's happening.", placement="bottom",
        ))
        db.session.commit()
        return tour.id


def test_guided_tours_admin_requires_admin_and_is_tenant_isolated(app, client):
    with app.app_context():
        db.session.add(Tenant(id=2, slug="tour-other", name="Other Tenant"))
        admin_id = User.query.filter_by(username="admin").one().id
        other_tour = GuidedTour(
            tenant_id=2, key="other-tour", title="Other Tenant Tour",
            created_by_id=admin_id,
        )
        db.session.add(other_tour)
        db.session.commit()
        other_tour_id = other_tour.id

    login(client, "database.manager", "Manager123!")
    not_admin = client.post("/admin/guided-tours", data={
        "action": "create", "key": "not-allowed", "title": "Nope", "target_route": "*",
    })
    assert not_admin.status_code == 403
    client.post("/logout")

    login(client)
    created = client.post("/admin/guided-tours", data={
        "action": "create", "key": "dashboard-intro", "title": "Dashboard tour",
        "description": "Intro", "target_route": "dashboard",
    })
    assert created.status_code == 302
    with app.app_context():
        tour = GuidedTour.query.filter_by(tenant_id=1, key="dashboard-intro").one()
        assert tour.version == 1

    listing = client.get("/admin/guided-tours")
    assert b"Other Tenant Tour" not in listing.data
    cross_tenant_toggle = client.post("/admin/guided-tours", data={
        "action": "toggle_active", "tour_id": other_tour_id,
    })
    assert cross_tenant_toggle.status_code == 404


def test_update_tour_and_add_step_bump_version(app, client):
    login(client)
    tour_id = _create_tour_with_step(app)
    with app.app_context():
        assert GuidedTour.query.get(tour_id).version == 1

    updated = client.post("/admin/guided-tours", data={
        "action": "update_tour", "tour_id": tour_id, "title": "Dashboard tour v2",
        "description": "Intro", "target_route": "dashboard",
    })
    assert updated.status_code == 302
    with app.app_context():
        assert GuidedTour.query.get(tour_id).version == 2

    added = client.post("/admin/guided-tours", data={
        "action": "add_step", "tour_id": tour_id, "step_title": "Second step",
        "step_body": "More detail.", "target_selector": "", "placement": "center",
    })
    assert added.status_code == 302
    with app.app_context():
        tour = GuidedTour.query.get(tour_id)
        assert tour.version == 3
        assert len(tour.steps) == 2


def test_active_tours_endpoint_matches_route_and_role_and_excludes_stepless_tours(app, client):
    login(client, "database.manager", "Manager123!")
    tour_id = _create_tour_with_step(app, target_route="dashboard", target_roles="manager")

    matching = client.get("/api/guided-tours/active?route=dashboard")
    assert matching.status_code == 200
    assert len(matching.json["tours"]) == 1
    assert matching.json["tours"][0]["id"] == tour_id
    assert matching.json["tours"][0]["steps"][0]["target_selector"] == "[data-tour='dashboard-stats']"

    wrong_route = client.get("/api/guided-tours/active?route=incidents_list")
    assert wrong_route.json["tours"] == []

    client.post("/logout")
    login(client, "employee", "Employee123!")  # role=requester, not in target_roles
    wrong_role = client.get("/api/guided-tours/active?route=dashboard")
    assert wrong_role.json["tours"] == []

    with app.app_context():
        empty_tour = GuidedTour(
            tenant_id=1, key="empty-tour", title="No steps yet", target_route="dashboard",
            created_by_id=User.query.filter_by(username="admin").one().id,
        )
        db.session.add(empty_tour)
        db.session.commit()
    still_empty = client.get("/api/guided-tours/active?route=dashboard")
    assert all(t["key"] != "empty-tour" for t in still_empty.json["tours"])


def test_progress_dismissal_hides_tour_until_version_bumps(app, client):
    login(client)
    tour_id = _create_tour_with_step(app, target_route="dashboard")

    first_check = client.get("/api/guided-tours/active?route=dashboard")
    assert len(first_check.json["tours"]) == 1

    dismissed = client.post(f"/api/guided-tours/{tour_id}/progress", data={"status": "dismissed"})
    assert dismissed.status_code == 204
    with app.app_context():
        progress = UserTourProgress.query.filter_by(tour_id=tour_id).one()
        assert progress.status == "dismissed"
        assert progress.tour_version_seen == 1

    after_dismiss = client.get("/api/guided-tours/active?route=dashboard")
    assert after_dismiss.json["tours"] == []

    client.post("/admin/guided-tours", data={
        "action": "update_tour", "tour_id": tour_id, "title": "Dashboard tour v2",
        "target_route": "dashboard",
    })
    re_prompted = client.get("/api/guided-tours/active?route=dashboard")
    assert len(re_prompted.json["tours"]) == 1


def test_progress_endpoint_rejects_invalid_status_and_cross_tenant_tour(app, client):
    login(client)
    tour_id = _create_tour_with_step(app)

    bad_status = client.post(f"/api/guided-tours/{tour_id}/progress", data={"status": "bogus"})
    assert bad_status.status_code == 400

    with app.app_context():
        db.session.add(Tenant(id=2, slug="tour-progress-other", name="Other Tenant"))
        other_admin = User(
            username="other.tour.admin", name="Other Tour Admin",
            email="other.tour.admin@test.invalid", password_hash="x", role="admin", tenant_id=2,
        )
        db.session.add(other_admin)
        db.session.flush()
        other_tour = GuidedTour(tenant_id=2, key="other", title="Other", created_by_id=other_admin.id)
        db.session.add(other_tour)
        db.session.commit()
        other_tour_id = other_tour.id

    cross_tenant = client.post(f"/api/guided-tours/{other_tour_id}/progress", data={"status": "dismissed"})
    assert cross_tenant.status_code == 404


def test_deleting_a_tour_with_recorded_progress_does_not_500(app, client):
    """UserTourProgress has no ORM/FK cascade from GuidedTour -- deleting a
    tour any user has actually seen must not leave a dangling FK reference
    or 500 (found via live browser verification: this was a real bug)."""
    login(client)
    tour_id = _create_tour_with_step(app, target_route="dashboard")
    recorded = client.post(f"/api/guided-tours/{tour_id}/progress", data={"status": "completed"})
    assert recorded.status_code == 204
    with app.app_context():
        assert UserTourProgress.query.filter_by(tour_id=tour_id).count() == 1

    deleted = client.post("/admin/guided-tours", data={"action": "delete", "tour_id": tour_id})
    assert deleted.status_code == 302
    with app.app_context():
        assert GuidedTour.query.filter_by(id=tour_id).first() is None
        assert UserTourProgress.query.filter_by(tour_id=tour_id).count() == 0
