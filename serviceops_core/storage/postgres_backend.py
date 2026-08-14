"""Default storage backend: today's PostgreSQL + local-disk/S3 attachment
storage, wrapped behind the StorageBackend interface with zero behavior
change. This is intentionally not a rewrite -- app.py's existing
db.session/Model.query call sites, the 83-file Alembic migration history,
and object_storage_enabled()/object_storage_client() are untouched; this
class only gives the attachment path a second caller (the new interface)
alongside the direct calls that remain in app.py during the multi-wave
migration described in the storage-mode plan.
"""
import os

from .interface import StorageBackend


class PostgresStorageBackend(StorageBackend):
    def __init__(self, upload_folder, object_storage_client_factory=None,
                 object_storage_bucket=None):
        self.upload_folder = upload_folder
        self._object_storage_client_factory = object_storage_client_factory
        self._object_storage_bucket = object_storage_bucket

    def _object_storage_enabled(self):
        return bool(self._object_storage_bucket)

    # -- Generic record CRUD: not used yet. app.py still calls
    # db.session/Model.query directly for every entity type except file
    # attachments; these raise on purpose so a future wave that forgets to
    # implement one fails loudly instead of silently doing nothing. --
    def get(self, entity_type, record_id):
        raise NotImplementedError(
            f"PostgresStorageBackend.get({entity_type!r}) not migrated yet -- "
            "call sites for this entity still use db.session/Model.query directly."
        )

    def create(self, entity_type, **fields):
        raise NotImplementedError(
            f"PostgresStorageBackend.create({entity_type!r}) not migrated yet."
        )

    def update(self, entity_type, record_id, **fields):
        raise NotImplementedError(
            f"PostgresStorageBackend.update({entity_type!r}) not migrated yet."
        )

    def delete(self, entity_type, record_id):
        raise NotImplementedError(
            f"PostgresStorageBackend.delete({entity_type!r}) not migrated yet."
        )

    def query(self, entity_type, tenant_id, filters=None, order_by=None,
              limit=None, offset=None):
        raise NotImplementedError(
            f"PostgresStorageBackend.query({entity_type!r}) not migrated yet."
        )

    def relate(self, entity_type, record_id, relation_name):
        raise NotImplementedError(
            f"PostgresStorageBackend.relate({entity_type!r}) not migrated yet."
        )

    def unit_of_work(self):
        raise NotImplementedError(
            "PostgresStorageBackend.unit_of_work() not migrated yet -- "
            "callers still use db.session.commit()/rollback() directly."
        )

    def enforce_unique(self, entity_type, fields):
        # A no-op by design: PostgreSQL already enforces this via real
        # unique constraints (see serviceops_models.py), so there is
        # nothing extra for this backend to check.
        return None

    # -- File attachments: real, in use today via app.py's
    # save_ticket_attachment()/attachment_download(). --
    def attach_file(self, path, data_bytes, content_type):
        if self._object_storage_enabled():
            client = self._object_storage_client_factory()
            client.put_object(
                Bucket=self._object_storage_bucket, Key=path,
                Body=data_bytes, ContentType=content_type,
            )
            return path
        local_path = os.path.join(self.upload_folder, path)
        with open(local_path, "wb") as handle:
            handle.write(data_bytes)
        return path

    def read_file(self, path, reference):
        if self._object_storage_enabled():
            client = self._object_storage_client_factory()
            response = client.get_object(Bucket=self._object_storage_bucket, Key=reference)
            return response["Body"].read(), response.get("ContentType")
        local_path = os.path.join(self.upload_folder, reference)
        with open(local_path, "rb") as handle:
            return handle.read(), None

    def delete_file(self, path, reference):
        if self._object_storage_enabled():
            client = self._object_storage_client_factory()
            try:
                client.delete_object(Bucket=self._object_storage_bucket, Key=reference)
            except Exception:
                pass
            return
        local_path = os.path.join(self.upload_folder, reference)
        try:
            os.remove(local_path)
        except FileNotFoundError:
            pass
