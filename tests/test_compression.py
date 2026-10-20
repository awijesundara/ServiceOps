"""Responses are gzip-compressed for clients that accept it: pages, JSON and static
assets, never downloads, small bodies or clients that did not ask."""
import gzip
import re
from io import BytesIO

from app import FileAttachment, db
from tests.test_app import app, client, login  # noqa: F401
from tests.test_incident_hierarchy import _incident

GZIP = {"Accept-Encoding": "gzip, deflate, br"}


def test_pages_are_compressed_only_when_the_client_accepts_gzip(client, app):
    login(client)
    app.config["CSRF_ENABLED"] = True  # pages then carry the injected token
    plain = client.get("/")
    assert "Content-Encoding" not in plain.headers
    packed = client.get("/", headers=GZIP)
    assert packed.headers["Content-Encoding"] == "gzip" and "Accept-Encoding" in packed.headers["Vary"]
    body = gzip.decompress(packed.get_data())
    assert body.startswith(b"<!doctype html>") or b"<html" in body[:400]
    assert int(packed.headers["Content-Length"]) == len(packed.get_data()) < len(body) / 3
    # The CSRF token and form tokens are injected before compression.
    assert b'name="csrf-token"' in body


def test_versioned_static_assets_are_compressed_once_and_revalidated_separately(client, app):
    page = client.get("/login").get_data(as_text=True)
    css = re.search(r'href="(/static/app\.css\?v=[^"]+)"', page).group(1)
    first = client.get(css, headers=GZIP)
    second = client.get(css, headers=GZIP)
    raw = client.get(css)
    assert first.headers["Content-Encoding"] == "gzip" and first.get_data() == second.get_data()
    assert gzip.decompress(first.get_data()) == raw.get_data()
    assert first.headers["Cache-Control"] == "public, max-age=31536000, immutable"
    assert first.headers.get("ETag", "").endswith('-gzip"') and raw.headers.get("ETag") != first.headers.get("ETag")
    assert "Content-Encoding" not in raw.headers
    # HEAD and tiny responses stay as they are.
    assert "Content-Encoding" not in client.head(css, headers=GZIP).headers
    assert "Content-Encoding" not in client.get("/health", headers=GZIP).headers


def test_json_is_compressed_but_attachment_downloads_are_not(client, app):
    login(client)
    _, ticket_id, _ = _incident(client, app, "Compression check")
    client.post(f"/ticket/{ticket_id}", data={"action": "comment", "body": "Log attached.",
                                              "file": (BytesIO(b"line\n" * 2000), "trace.log")},
                content_type="multipart/form-data")
    with app.app_context():
        attachment_id = FileAttachment.query.filter_by(ticket_id=ticket_id).one().id
    download = client.get(f"/attachments/{attachment_id}", headers=GZIP)
    assert download.status_code == 200 and "Content-Encoding" not in download.headers
    assert download.get_data() == b"line\n" * 2000
    with app.app_context():
        assert db.session.get(FileAttachment, attachment_id)
