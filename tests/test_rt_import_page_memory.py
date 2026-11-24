"""The Request Tracker import page must stay small however large stored job results are.

Imports run before results were capped stored every preview row and error; the page loaded and
parsed them about ten times per job and the web worker was OOM-killed.
"""
import json
import time

from app import PlatformSetting, RTImportJob, User, db
from serviceops_core import rt_import
from tests.test_app import app, client, login  # noqa: F401 - fixtures


def _job(admin_id, result, dry_run=False):
    job = RTImportJob(tenant_id=1, actor_user_id=admin_id, search_query="id > 0", dry_run=dry_run,
                      status="Completed", result_json=json.dumps(result))
    db.session.add(job)
    return job


def test_page_shows_counts_of_a_huge_old_result_without_loading_it(client, app, monkeypatch):
    with app.app_context():
        db.session.add(PlatformSetting(key="RT_ENABLED", value="true", encrypted=False))
        admin_id = User.query.filter_by(username="admin").one().id
        huge = {"tickets_seen": 9000, "records_created": 8800, "events_created": 8700, "changes_created": 100,
                "already_imported": 200, "attachments_imported": 12,
                "errors": [f"RT #{i}: something odd " + "x" * 200 for i in range(60000)],
                "preview": [{"rt_id": str(i), "title": "t" * 200} for i in range(60000)]}
        _job(admin_id, huge)
        db.session.commit()
    parsed = []
    real_loads = json.loads
    monkeypatch.setattr(rt_import.json, "loads", lambda s, *a, **k: parsed.append(len(s)) or real_loads(s, *a, **k))
    login(client)
    started = time.monotonic()
    response = client.get("/tickets/import/rt")
    assert response.status_code == 200
    assert time.monotonic() - started < 5
    assert b"8800" in response.data and b"too large to show" in response.data
    assert not [n for n in parsed if n > 1024 * 1024], "the oversized result must not be parsed"


def test_page_shows_the_first_100_errors_and_preview_rows(client, app):
    with app.app_context():
        db.session.add(PlatformSetting(key="RT_ENABLED", value="true", encrypted=False))
        admin_id = User.query.filter_by(username="admin").one().id
        result = {"tickets_seen": 300, "records_created": 300, "events_created": 300, "changes_created": 0,
                  "already_imported": 0, "attachments_imported": 0, "dry_run": True,
                  "errors": [f"problem {i}" for i in range(250)],
                  "preview": [{"rt_id": str(i), "type": "IT operations event", "title": f"T{i}"} for i in range(250)]}
        _job(admin_id, result, dry_run=True)
        db.session.commit()
    login(client)
    page = client.get("/tickets/import/rt").get_data(as_text=True)
    assert "problem 99" in page and "problem 100" not in page
    assert "Showing the first 100 of 250" in page
    assert ">T99<" in page and ">T100<" not in page


def test_summary_is_bounded():
    view = rt_import.summarize_result({"records_created": 5, "errors": ["e"] * 900, "preview": [{"rt_id": "1"}] * 900})
    assert len(view["errors"]) == rt_import.RESULT_VIEW_ITEMS and view["errors_total"] == 900
    head = rt_import.summarize_result_head('{"tenant_id": 1, "dry_run": false, "tickets_seen": 12, "records_created": 7, "errors": [')
    assert head["records_created"] == 7 and head["truncated"]
