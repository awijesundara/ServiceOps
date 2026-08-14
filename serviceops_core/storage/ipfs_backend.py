"""IPFS-backed storage: the optional, database-less deployment mode.

This first slice implements only file attachments end-to-end (the
storage-mode plan's "suggested first concrete slice") plus the
checkpoint boot/save mechanism that every future wave will reuse. Record
CRUD for ITIL entities (tickets, changes, CIs, ...) is a later wave and
raises NotImplementedError here on purpose -- see interface.py.

State model: `self._file_index` maps a caller-chosen storage key (e.g.
FileAttachment.stored_name) to its current IPFS CID. This is the entire
"database" this backend keeps, and it exists only in memory. At boot,
`load_checkpoint()` resolves the instance's IPNS name to the latest
checkpoint object, fetches and decrypts it, and populates `_file_index`
from it. Every write updates `_file_index` immediately (so reads stay
fast and don't round-trip to IPFS) and calls `save_checkpoint()`, which
re-serializes the whole index, encrypts it, adds it to IPFS, and
republishes the IPNS pointer -- so a restart only ever needs the single
latest checkpoint, not a replay of full history.

Every file's bytes are Fernet-encrypted (same key as the checkpoint)
before being added to IPFS, and decrypted on read -- see attach_file()'s
comment for why this isn't optional.
"""
import logging

from cryptography.fernet import Fernet

from .checkpoint import decrypt_checkpoint, encrypt_checkpoint
from .interface import StorageBackend
from .ipfs_client import IPFSClient

logger = logging.getLogger("serviceops.storage.ipfs")

CHECKPOINT_KEY_NAME = "serviceops-checkpoint"


class IPFSStorageBackend(StorageBackend):
    def __init__(self, api_url, checkpoint_encryption_key, client=None):
        self.client = client or IPFSClient(api_url)
        self._checkpoint_key = checkpoint_encryption_key
        self._file_index = {}
        self._checkpoint_name = None

    # -- Checkpoint boot/save --------------------------------------------
    def load_checkpoint(self):
        """Resolve the instance's IPNS pointer and load the latest
        checkpoint into memory. Safe to call on a fresh node with no
        checkpoint published yet -- starts with an empty index."""
        self._checkpoint_name = self.client.key_gen(CHECKPOINT_KEY_NAME)
        cid = self.client.name_resolve(self._checkpoint_name)
        if not cid:
            logger.info("No existing IPFS checkpoint found; starting with an empty index.")
            return
        try:
            encrypted = self.client.cat(cid)
            state = decrypt_checkpoint(encrypted, self._checkpoint_key)
        except Exception:
            logger.exception("Failed to load IPFS checkpoint %s; starting with an empty index.", cid)
            return
        self._file_index = state.get("file_index", {})
        logger.info("Loaded IPFS checkpoint %s: %d file(s) indexed.", cid, len(self._file_index))

    def save_checkpoint(self):
        """Re-snapshot the full in-memory index to IPFS and republish the
        IPNS pointer. Called after every write in this first slice; a
        later wave can debounce this (time- or write-count based) once
        real usage volume makes synchronous republish-per-write too slow
        -- correctness first, then throughput."""
        if self._checkpoint_name is None:
            self._checkpoint_name = self.client.key_gen(CHECKPOINT_KEY_NAME)
        state = {"file_index": self._file_index}
        encrypted = encrypt_checkpoint(state, self._checkpoint_key)
        cid = self.client.add_bytes(encrypted, filename="checkpoint")
        self.client.pin_add(cid)
        self.client.name_publish(cid, CHECKPOINT_KEY_NAME)
        return cid

    # -- Generic record CRUD: later wave. -------------------------------
    def get(self, entity_type, record_id):
        raise NotImplementedError(
            f"IPFSStorageBackend.get({entity_type!r}) is a later rollout wave -- "
            "only file attachments are implemented in this slice."
        )

    def create(self, entity_type, **fields):
        raise NotImplementedError(f"IPFSStorageBackend.create({entity_type!r}) not implemented yet.")

    def update(self, entity_type, record_id, **fields):
        raise NotImplementedError(f"IPFSStorageBackend.update({entity_type!r}) not implemented yet.")

    def delete(self, entity_type, record_id):
        raise NotImplementedError(f"IPFSStorageBackend.delete({entity_type!r}) not implemented yet.")

    def query(self, entity_type, tenant_id, filters=None, order_by=None,
              limit=None, offset=None):
        raise NotImplementedError(f"IPFSStorageBackend.query({entity_type!r}) not implemented yet.")

    def relate(self, entity_type, record_id, relation_name):
        raise NotImplementedError(f"IPFSStorageBackend.relate({entity_type!r}) not implemented yet.")

    def unit_of_work(self):
        raise NotImplementedError("IPFSStorageBackend.unit_of_work() not implemented yet.")

    def enforce_unique(self, entity_type, fields):
        # The in-memory file index is the only state this slice keeps, and
        # attach_file()'s caller (FileAttachment.stored_name) already
        # guarantees uniqueness via uuid4-prefixed names -- nothing to
        # enforce here yet. A real per-entity check lands with each
        # entity's own rollout wave.
        return None

    # -- File attachments: real, implemented in this slice. --------------
    def attach_file(self, path, data_bytes, content_type):
        # Encrypted before it ever leaves this process: public IPFS (or
        # any pinning service/gateway under IPFS_MODE=external) has no
        # access control of its own -- anyone who obtains a CID can fetch
        # its content directly, bypassing every ServiceOps authorization
        # check entirely. Confidentiality here comes only from encryption,
        # never from the CID being hard to guess. Found and fixed after a
        # live test showed a stored attachment's plaintext readable
        # straight off the (private, single-node) Kubo daemon, with no
        # app-level auth involved at all.
        encrypted = Fernet(self._checkpoint_key).encrypt(data_bytes)
        cid = self.client.add_bytes(encrypted, filename=path)
        self.client.pin_add(cid)
        self._file_index[path] = cid
        self.save_checkpoint()
        return cid

    def read_file(self, path, reference):
        cid = reference or self._file_index.get(path)
        if not cid:
            raise FileNotFoundError(path)
        encrypted = self.client.cat(cid)
        return Fernet(self._checkpoint_key).decrypt(encrypted), None

    def delete_file(self, path, reference):
        cid = reference or self._file_index.get(path)
        was_indexed = self._file_index.pop(path, None) is not None
        if cid:
            self.client.pin_rm(cid)
        if was_indexed:
            self.save_checkpoint()
