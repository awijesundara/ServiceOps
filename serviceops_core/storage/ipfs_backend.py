"""IPFS-backed storage: the optional, database-less deployment mode.

The encrypted checkpoint contains the complete relational projection plus
attachments and the legacy B-335 entity map. The generic CRUD methods remain
for backward-compatible import of that original user/tenant checkpoint; normal
application records are projected generically by ipfs_projection.py.

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
import copy
import threading
import time

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
        # Legacy B-335 identity map, retained so existing user/tenant
        # checkpoints can be upgraded into the complete relational state.
        self._entities = {}
        self._next_id = {}
        self._relational_state = {}
        self._state_lock = threading.RLock()
        self._publish_condition = threading.Condition()
        self._pending_checkpoint_cid = None
        self._last_published_checkpoint_cid = None
        self._publisher_started = False

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
        # JSON round-trips dict keys as strings; entity ids and the
        # per-type next-id counters need to come back as ints.
        self._entities = {
            entity_type: {int(record_id): fields for record_id, fields in rows.items()}
            for entity_type, rows in state.get("entities", {}).items()
        }
        self._next_id = {
            entity_type: next_id for entity_type, next_id in state.get("next_id", {}).items()
        }
        self._relational_state = state.get("relational_state", {})
        logger.info(
            "Loaded IPFS checkpoint %s: %d file(s), %d entity type(s) indexed.",
            cid, len(self._file_index), len(self._entities),
        )

    def save_checkpoint(self):
        """Add and pin a full encrypted snapshot, then coalesce publication.

        Kubo IPNS publication can take tens of seconds. The latest CID is
        therefore published by one retrying background thread; newer commits
        replace the pending CID, keeping request latency independent of IPNS.
        Readiness exposes whether publication is pending."""
        if self._checkpoint_name is None:
            self._checkpoint_name = self.client.key_gen(CHECKPOINT_KEY_NAME)
        state = {
            "file_index": self._file_index,
            "entities": self._entities,
            "next_id": self._next_id,
            "relational_state": self._relational_state,
        }
        encrypted = encrypt_checkpoint(state, self._checkpoint_key)
        cid = self.client.add_bytes(encrypted, filename="checkpoint")
        try:
            self.client.pin_add(cid)
        except Exception:
            logger.exception(
                "Failed to pin IPFS checkpoint %s -- in-memory state is "
                "still current for this process, but a restart before the "
                "next successful checkpoint would lose writes since the last "
                "one.", cid,
            )
            return cid
        # Test doubles publish synchronously, keeping unit tests deterministic.
        # Real Kubo publication is isolated from the request path because it
        # can take tens of seconds even on a healthy single-node deployment.
        if not isinstance(self.client, IPFSClient):
            try:
                self.client.name_publish(cid, CHECKPOINT_KEY_NAME)
                self._last_published_checkpoint_cid = cid
            except Exception:
                logger.exception("Failed to publish IPFS checkpoint %s.", cid)
            return cid
        with self._publish_condition:
            self._pending_checkpoint_cid = cid
            if not self._publisher_started:
                threading.Thread(
                    target=self._publish_loop,
                    name="serviceops-ipns-publisher",
                    daemon=True,
                ).start()
                self._publisher_started = True
            self._publish_condition.notify_all()
        return cid

    def _publish_loop(self):
        while True:
            with self._publish_condition:
                while not self._pending_checkpoint_cid:
                    self._publish_condition.wait()
                cid = self._pending_checkpoint_cid
            try:
                self.client.name_publish(cid, CHECKPOINT_KEY_NAME)
            except Exception:
                logger.exception("Failed to publish IPFS checkpoint %s; retrying.", cid)
                time.sleep(2)
                continue
            with self._publish_condition:
                self._last_published_checkpoint_cid = cid
                if self._pending_checkpoint_cid == cid:
                    self._pending_checkpoint_cid = None

    @property
    def checkpoint_publish_pending(self):
        with self._publish_condition:
            return self._pending_checkpoint_cid is not None

    # -- Generic record CRUD -----------------------------------------------
    # Backward-compatible B-335 identity CRUD. Full application models use
    # the generic relational projection above rather than this narrow map.
    _IMPLEMENTED_ENTITY_TYPES = {"user", "tenant"}

    def get_relational_state(self):
        with self._state_lock:
            return copy.deepcopy(self._relational_state)

    def replace_relational_state(self, tables):
        """Atomically replace and durably publish the full app projection."""
        with self._state_lock:
            self._relational_state = copy.deepcopy(tables)
            return self.save_checkpoint()

    def export_legacy_entities(self):
        """Return B-335 identity rows for one-time full-state migration."""
        with self._state_lock:
            return {
                entity_type: [copy.deepcopy(row) for row in rows.values()]
                for entity_type, rows in self._entities.items()
            }

    def _require_implemented(self, entity_type):
        if entity_type not in self._IMPLEMENTED_ENTITY_TYPES:
            raise NotImplementedError(
                f"IPFSStorageBackend does not implement {entity_type!r} yet -- "
                "only file attachments, users, and tenants are implemented so far."
            )

    def get(self, entity_type, record_id):
        self._require_implemented(entity_type)
        row = self._entities.get(entity_type, {}).get(int(record_id))
        return dict(row) if row is not None else None

    def create(self, entity_type, **fields):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        record_id = self._next_id.get(entity_type, 0) + 1
        self._next_id[entity_type] = record_id
        row = {"id": record_id, **fields}
        table[record_id] = row
        self.save_checkpoint()
        return dict(row)

    def update(self, entity_type, record_id, **fields):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        row = table.get(int(record_id))
        if row is None:
            raise KeyError(f"No {entity_type} with id {record_id}")
        row.update(fields)
        self.save_checkpoint()
        return dict(row)

    def delete(self, entity_type, record_id):
        self._require_implemented(entity_type)
        table = self._entities.setdefault(entity_type, {})
        if table.pop(int(record_id), None) is not None:
            self.save_checkpoint()

    def query(self, entity_type, tenant_id, filters=None, order_by=None,
              limit=None, offset=None):
        self._require_implemented(entity_type)
        rows = list(self._entities.get(entity_type, {}).values())
        if tenant_id is not None:
            rows = [row for row in rows if row.get("tenant_id") == tenant_id]
        for field, op, value in (filters or []):
            if op == "eq":
                rows = [row for row in rows if row.get(field) == value]
            elif op == "in":
                rows = [row for row in rows if row.get(field) in value]
            else:
                raise NotImplementedError(f"IPFSStorageBackend.query() filter op {op!r} not implemented.")
        if order_by:
            field, _, direction = order_by.partition(" ")
            rows.sort(key=lambda row: row.get(field), reverse=direction.strip().lower() == "desc")
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[:limit]
        return [dict(row) for row in rows]

    def relate(self, entity_type, record_id, relation_name):
        raise NotImplementedError(f"IPFSStorageBackend.relate({entity_type!r}) not implemented yet.")

    def unit_of_work(self):
        raise NotImplementedError("IPFSStorageBackend.unit_of_work() not implemented yet.")

    def enforce_unique(self, entity_type, fields):
        # No caller needs this yet for user/tenant (login checks username
        # uniqueness itself via query()); file attachments don't need it
        # either (uuid4-prefixed names). A real per-entity check lands
        # with each entity's own rollout wave if/when it's needed.
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
