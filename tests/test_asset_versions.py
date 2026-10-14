"""Static asset URLs change whenever a static file changes, not only on a
release: assets are served immutable, so an unchanged ?v= would keep
browsers on the old file after a deploy."""
import re

import app as app_module
from tests.test_app import app, client, login  # noqa: F401


def test_asset_urls_and_service_worker_carry_the_static_fingerprint(app, client):
    version = app_module.static_asset_version(app.static_folder)
    assert re.fullmatch(re.escape(app_module.APP_VERSION) + r"-[0-9a-f]{10}", version)
    page = client.get("/login").get_data(as_text=True)
    assert f"app.css?v={version}" in page and f"platform.js?v={version}" in page
    assert f"?v={app_module.APP_VERSION}\"" not in page
    worker = client.get("/service-worker.js")
    body = worker.get_data(as_text=True)
    assert f'serviceops-shell-v{version}"' in body and f"/static/app.css?v={version}" in body
    assert worker.headers["Cache-Control"] == "no-cache"


def test_the_fingerprint_follows_the_files(tmp_path):
    (tmp_path / "a.css").write_text("a{color:red}")
    first = app_module.static_asset_version(str(tmp_path))
    app_module._asset_fingerprints.clear()
    (tmp_path / "a.css").write_text("a{color:teal}")
    assert app_module.static_asset_version(str(tmp_path)) != first
    app_module._asset_fingerprints.clear()
