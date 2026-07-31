"""Tests that RT import is queued and run in the background instead of
synchronously inside the web request -- the synchronous version routinely
exceeded gunicorn's worker timeout against a real (slow) RT instance,
which kills the whole worker process, not just that request.
"""
from app import PlatformSetting, RTImportJob, User, db, process_rt_import_jobs
from tests.test_app import app, client, login


def test_rt_import_route_enqueues_job_instead_of_running_synchronously(client, app):
    with app.app_context():
        db.session.add(PlatformSetting(key="RT_ENABLED", value="true", encrypted=False))
        db.session.commit()
    login(client)

    response = client.post("/tickets/import/rt", data={"query": "id > 0", "dry_run": "1"})
    assert response.status_code == 302

    with app.app_context():
        job = RTImportJob.query.one()
        assert job.status == "Pending"
        assert job.dry_run is True
        assert job.search_query == "id > 0"


def test_rt_import_route_refuses_to_queue_when_disabled(client, app):
    login(client)
    response = client.post("/tickets/import/rt", data={"query": "id > 0", "dry_run": "1"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"not enabled" in response.data
    with app.app_context():
        assert RTImportJob.query.count() == 0


def test_process_rt_import_jobs_runs_pending_job_and_records_result(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        job = RTImportJob(tenant_id=1, actor_user_id=admin_id, search_query="id > 0", dry_run=True)
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    fake_result = {
        "tickets_seen": 3, "records_created": 1, "already_imported": 2,
        "events_created": 1, "changes_created": 0, "teams_created": 0,
        "users_created": 0, "comments_imported": 0, "attachments_imported": 0,
        "errors": [], "preview": [],
    }

    import serviceops_core.rt_import as rt_import_module
    monkeypatch.setattr(rt_import_module, "import_from_rt", lambda *args, **kwargs: fake_result)

    with app.app_context():
        processed = process_rt_import_jobs()
        assert processed == 1
        updated = db.session.get(RTImportJob, job_id)
        assert updated.status == "Completed"
        assert updated.started_at is not None
        assert updated.finished_at is not None
        assert updated.result["records_created"] == 1


def test_process_rt_import_jobs_marks_failure_without_crashing_the_worker(app, monkeypatch):
    with app.app_context():
        admin_id = User.query.filter_by(username="admin").one().id
        job = RTImportJob(tenant_id=1, actor_user_id=admin_id, search_query="id > 0", dry_run=True)
        db.session.add(job)
        db.session.commit()
        job_id = job.id

    import serviceops_core.rt_import as rt_import_module

    def boom(*args, **kwargs):
        raise RuntimeError("RT instance timed out")

    monkeypatch.setattr(rt_import_module, "import_from_rt", boom)

    with app.app_context():
        processed = process_rt_import_jobs()
        assert processed == 1
        updated = db.session.get(RTImportJob, job_id)
        assert updated.status == "Failed"
        assert "RT instance timed out" in updated.error
