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
import logging

from .interface import StorageBackend


class PostgresStorageBackend(StorageBackend):
    def __init__(self, upload_folder, object_storage_client_factory=None,
                 object_storage_bucket=None):
        self.upload_folder = upload_folder
        self._object_storage_client_factory = object_storage_client_factory
        self._object_storage_bucket = object_storage_bucket

    def _object_storage_enabled(self):
        return bool(self._object_storage_bucket)

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
            try:
                client = self._object_storage_client_factory()
                client.delete_object(Bucket=self._object_storage_bucket, Key=reference)
            except Exception:
                logging.getLogger(__name__).error("Object-storage attachment deletion failed")
            return
        local_path = os.path.join(self.upload_folder, reference)
        try:
            os.remove(local_path)
        except FileNotFoundError:
            return
        except OSError:
            logging.getLogger(__name__).error("Local attachment deletion failed")
