"""Tests for tools/migrate_local_attachments_to_object_storage.py (B-052's
disclosed local-to-S3 migration gap). Real end-to-end behavior against a
genuine S3-compatible backend (MinIO) was verified manually in a disposable
rehearsal; these tests cover the tool's decision logic with a fake client.
"""
import hashlib
import os

from app import FileAttachment, User, db
from tests.test_app import app
from tools.migrate_local_attachments_to_object_storage import migrate


class _FakeBody:
    def __init__(self, data):
        self._data = data

    def iter_chunks(self, chunk_size):
        yield self._data


class _FakeS3Client:
    def __init__(self, store, fail_keys=()):
        self.store = store
        self.fail_keys = set(fail_keys)

    def upload_file(self, path, bucket, key, ExtraArgs=None):
        if key in self.fail_keys:
            raise Exception("simulated upload failure")
        with open(path, "rb") as handle:
            self.store[key] = handle.read()

    def get_object(self, Bucket, Key):
        return {"Body": _FakeBody(self.store[Key])}


def _create_attachment(app, content=b"hello migration"):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        stored = "migrate-test-stored-name.txt"
        upload_folder = app.config["UPLOAD_FOLDER"]
        path = os.path.join(upload_folder, stored)
        with open(path, "wb") as handle:
            handle.write(content)
        attachment = FileAttachment(
            uploaded_by_id=admin.id, original_name="original.txt", stored_name=stored,
            mime_type="text/plain", size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(), scan_status="clean",
        )
        db.session.add(attachment)
        db.session.commit()
        return attachment.id, path


def test_migrate_uploads_and_removes_local_file_on_success(app, monkeypatch):
    attachment_id, path = _create_attachment(app)
    store = {}
    monkeypatch.setattr("tools.migrate_local_attachments_to_object_storage.object_storage_enabled", lambda: True)
    monkeypatch.setattr(
        "tools.migrate_local_attachments_to_object_storage.object_storage_client",
        lambda: _FakeS3Client(store),
    )
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "test-bucket")
    with app.app_context():
        result = migrate()
    assert result == 0
    assert not os.path.exists(path)
    assert "migrate-test-stored-name.txt" in store


def test_migrate_keeps_local_file_on_upload_failure(app, monkeypatch):
    attachment_id, path = _create_attachment(app)
    store = {}
    monkeypatch.setattr("tools.migrate_local_attachments_to_object_storage.object_storage_enabled", lambda: True)
    monkeypatch.setattr(
        "tools.migrate_local_attachments_to_object_storage.object_storage_client",
        lambda: _FakeS3Client(store, fail_keys={"migrate-test-stored-name.txt"}),
    )
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "test-bucket")
    with app.app_context():
        result = migrate()
    assert result == 1
    assert os.path.exists(path)  # local copy preserved after a failed upload


def test_migrate_skips_attachments_already_missing_locally(app, monkeypatch):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        attachment = FileAttachment(
            uploaded_by_id=admin.id, original_name="gone.txt", stored_name="already-migrated.txt",
            mime_type="text/plain", size_bytes=5, sha256="x" * 64, scan_status="clean",
        )
        db.session.add(attachment)
        db.session.commit()

    monkeypatch.setattr("tools.migrate_local_attachments_to_object_storage.object_storage_enabled", lambda: True)
    monkeypatch.setattr(
        "tools.migrate_local_attachments_to_object_storage.object_storage_client",
        lambda: _FakeS3Client({}),
    )
    monkeypatch.setenv("OBJECT_STORAGE_BUCKET", "test-bucket")
    with app.app_context():
        result = migrate()
    assert result == 0
