"""Storage backend selection. See serviceops_core/storage/interface.py
for the full design and the storage-mode plan for the rollout waves.

STORAGE_MODE=postgres (default) keeps today's PostgreSQL + local-disk/S3
attachment behavior, byte-for-byte, via PostgresStorageBackend.
STORAGE_MODE=ipfs is the new, experimental, database-less mode.
"""
import os

from .interface import StorageBackend  # noqa: F401 -- re-exported
from .postgres_backend import PostgresStorageBackend


def storage_mode():
    return os.getenv("STORAGE_MODE", "postgres").strip().lower()


def ipfs_enabled():
    return storage_mode() == "ipfs"


def build_storage_backend(upload_folder=None, object_storage_client_factory=None,
                           object_storage_bucket=None):
    """Constructs the active backend from environment configuration. Called
    once at app boot (see app.py); the result is held for the process
    lifetime, matching how `db` itself is a single long-lived object today."""
    if ipfs_enabled():
        from .checkpoint import derive_checkpoint_key
        from .ipfs_backend import IPFSStorageBackend
        key = derive_checkpoint_key(
            os.getenv("SETTINGS_ENCRYPTION_KEY", ""),
            os.environ["SECRET_KEY"],
        )
        provider = os.getenv("IPFS_PROVIDER", "kubo").strip().lower()
        if provider == "pinata":
            # Free, hosted alternative to a self-hosted Kubo node -- no
            # bundled/external IPFS container to run at all. See
            # pinata_client.py for why the checkpoint pointer works
            # differently here (named-file versioning, not IPNS).
            from .pinata_client import PinataIPFSClient
            client = PinataIPFSClient(
                os.environ["PINATA_JWT"],
                gateway=os.getenv("PINATA_GATEWAY_URL", "").strip() or None,
            )
            backend = IPFSStorageBackend(api_url=None, checkpoint_encryption_key=key, client=client)
        else:
            api_url = os.environ["IPFS_API_URL"]
            backend = IPFSStorageBackend(api_url, key)
        backend.load_checkpoint()
        return backend
    return PostgresStorageBackend(
        upload_folder=upload_folder,
        object_storage_client_factory=object_storage_client_factory,
        object_storage_bucket=object_storage_bucket,
    )
