"""Unit tests for serviceops_core/storage/ -- the seam behind the optional
database-less (STORAGE_MODE=ipfs) deployment mode's first slice: the
StorageBackend interface, the PostgreSQL adapter's file-attachment path
(byte-for-byte the same behavior as today), and the new IPFS backend's
file-attachment + checkpoint boot/save mechanism, exercised against a
fake in-memory IPFS node (no real Kubo instance required for this suite --
see test_ipfs_backend_live.py, gated behind a real node, for that).
"""
import base64
import hashlib

import pytest
from cryptography.fernet import Fernet

from serviceops_core.storage.checkpoint import (
    decrypt_checkpoint, derive_checkpoint_key, encrypt_checkpoint,
)
from serviceops_core.storage.interface import StorageBackend
from serviceops_core.storage.ipfs_backend import IPFSStorageBackend
from serviceops_core.storage.postgres_backend import PostgresStorageBackend


# -- interface contract -------------------------------------------------

def test_storage_backend_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        StorageBackend()


def test_postgres_and_ipfs_backends_implement_the_full_interface():
    # Both concrete classes must actually satisfy every abstract method --
    # a missing override would raise TypeError at instantiation.
    PostgresStorageBackend(upload_folder="/tmp")
    IPFSStorageBackend(api_url="http://127.0.0.1:5001", checkpoint_encryption_key=Fernet.generate_key())


# -- checkpoint encryption ------------------------------------------------

def test_checkpoint_round_trips_through_encryption():
    key = Fernet.generate_key()
    state = {"file_index": {"a-file.txt": "bafy...cid1", "b-file.png": "bafy...cid2"}}
    encrypted = encrypt_checkpoint(state, key)
    assert encrypted != state
    decrypted = decrypt_checkpoint(encrypted, key)
    assert decrypted == state


def test_checkpoint_wrong_key_fails_to_decrypt():
    state = {"file_index": {}}
    encrypted = encrypt_checkpoint(state, Fernet.generate_key())
    with pytest.raises(Exception):
        decrypt_checkpoint(encrypted, Fernet.generate_key())


def test_derive_checkpoint_key_prefers_settings_encryption_key():
    explicit = Fernet.generate_key()
    assert derive_checkpoint_key(explicit.decode(), "irrelevant-secret-key") == explicit


def test_derive_checkpoint_key_falls_back_to_secret_key_like_settings_cipher():
    # Mirrors serviceops_models.settings_cipher()'s fallback exactly, so an
    # operator who never set SETTINGS_ENCRYPTION_KEY gets the same
    # deterministic key derivation IPFS mode's checkpoint encryption uses.
    secret = "a" * 32
    digest = hashlib.sha256(secret.encode()).digest()
    expected = base64.urlsafe_b64encode(digest)
    assert derive_checkpoint_key("", secret) == expected


# -- PostgresStorageBackend: local disk (default, no behavior change) ----

def test_postgres_backend_attach_read_delete_file_local_disk(tmp_path):
    backend = PostgresStorageBackend(upload_folder=str(tmp_path))
    ref = backend.attach_file("myfile.txt", b"hello world", "text/plain")
    assert ref == "myfile.txt"
    assert (tmp_path / "myfile.txt").read_bytes() == b"hello world"
    data, _ = backend.read_file("myfile.txt", ref)
    assert data == b"hello world"
    backend.delete_file("myfile.txt", ref)
    assert not (tmp_path / "myfile.txt").exists()
    # Matches today's local-disk behavior: deleting an already-missing file
    # is not an error.
    backend.delete_file("myfile.txt", ref)


def test_postgres_backend_attach_read_delete_file_object_storage():
    calls = []

    class FakeS3Client:
        def put_object(self, Bucket, Key, Body, ContentType):
            calls.append(("put", Bucket, Key, Body, ContentType))

        def get_object(self, Bucket, Key):
            calls.append(("get", Bucket, Key))
            class Body:
                def read(self_inner):
                    return b"from s3"
            return {"Body": Body(), "ContentType": "text/plain"}

        def delete_object(self, Bucket, Key):
            calls.append(("delete", Bucket, Key))

    backend = PostgresStorageBackend(
        upload_folder="/unused", object_storage_client_factory=FakeS3Client,
        object_storage_bucket="my-bucket",
    )
    ref = backend.attach_file("myfile.txt", b"hello", "text/plain")
    assert ref == "myfile.txt"
    assert calls[0] == ("put", "my-bucket", "myfile.txt", b"hello", "text/plain")
    data, content_type = backend.read_file("myfile.txt", ref)
    assert data == b"from s3"
    assert content_type == "text/plain"
    backend.delete_file("myfile.txt", ref)
    assert calls[-1] == ("delete", "my-bucket", "myfile.txt")


# -- IPFSStorageBackend: fake in-memory Kubo node -------------------------

class FakeIPFSClient:
    """Stands in for a real Kubo node -- an in-memory content-addressed
    store plus one named IPNS pointer, enough to exercise
    IPFSStorageBackend's real logic without a live IPFS node."""

    def __init__(self):
        self._blobs = {}
        self._pins = set()
        self._keys = {}
        self._ipns = {}
        self._next_cid = 0

    def add_bytes(self, data_bytes, filename="blob"):
        self._next_cid += 1
        cid = f"fake-cid-{self._next_cid}"
        self._blobs[cid] = data_bytes
        return cid

    def cat(self, cid):
        return self._blobs[cid]

    def pin_add(self, cid):
        self._pins.add(cid)

    def pin_rm(self, cid):
        self._pins.discard(cid)

    def key_list(self):
        return dict(self._keys)

    def key_gen(self, name):
        if name not in self._keys:
            self._keys[name] = f"fake-peer-id-{name}"
        return self._keys[name]

    def name_publish(self, cid, key_name):
        self._ipns[key_name] = cid

    def name_resolve(self, name_or_peer_id):
        for key_name, peer_id in self._keys.items():
            if peer_id == name_or_peer_id:
                return self._ipns.get(key_name)
        return None

    def node_id(self):
        return "fake-node-id"


@pytest.fixture
def ipfs_backend():
    return IPFSStorageBackend(
        api_url="http://unused", checkpoint_encryption_key=Fernet.generate_key(),
        client=FakeIPFSClient(),
    )


def test_ipfs_backend_load_checkpoint_on_fresh_node_starts_empty(ipfs_backend):
    ipfs_backend.load_checkpoint()
    assert ipfs_backend._file_index == {}


def test_ipfs_backend_attach_read_delete_file(ipfs_backend):
    ipfs_backend.load_checkpoint()
    cid = ipfs_backend.attach_file("report.pdf", b"pdf bytes", "application/pdf")
    assert cid in ipfs_backend.client._blobs
    assert cid in ipfs_backend.client._pins
    assert ipfs_backend._file_index["report.pdf"] == cid

    data, _ = ipfs_backend.read_file("report.pdf", cid)
    assert data == b"pdf bytes"
    # Reading by path alone (no explicit reference) also works, since the
    # in-memory index is authoritative for "what CID is this file at."
    data_by_path, _ = ipfs_backend.read_file("report.pdf", None)
    assert data_by_path == b"pdf bytes"

    ipfs_backend.delete_file("report.pdf", cid)
    assert "report.pdf" not in ipfs_backend._file_index
    assert cid not in ipfs_backend.client._pins


def test_ipfs_backend_read_missing_file_raises(ipfs_backend):
    ipfs_backend.load_checkpoint()
    with pytest.raises(FileNotFoundError):
        ipfs_backend.read_file("nope.txt", None)


def test_ipfs_backend_checkpoint_survives_a_reload(ipfs_backend):
    """The core claim of the "no local index" design: a brand-new backend
    instance pointed at the same (fake) node recovers the full file index
    by resolving the IPNS pointer and loading the latest checkpoint --
    nothing is read from local disk."""
    ipfs_backend.load_checkpoint()
    ipfs_backend.attach_file("a.txt", b"aaa", "text/plain")
    ipfs_backend.attach_file("b.txt", b"bbb", "text/plain")

    reloaded = IPFSStorageBackend(
        api_url="http://unused", checkpoint_encryption_key=ipfs_backend._checkpoint_key,
        client=ipfs_backend.client,
    )
    reloaded.load_checkpoint()
    assert reloaded._file_index == ipfs_backend._file_index
    data, _ = reloaded.read_file("a.txt", None)
    assert data == b"aaa"


def test_ipfs_backend_reload_with_wrong_key_starts_empty_not_crashes(ipfs_backend):
    # A misconfigured SETTINGS_ENCRYPTION_KEY on a fresh instance must fail
    # safe (empty index, logged) rather than crash app boot.
    ipfs_backend.load_checkpoint()
    ipfs_backend.attach_file("a.txt", b"aaa", "text/plain")

    reloaded = IPFSStorageBackend(
        api_url="http://unused", checkpoint_encryption_key=Fernet.generate_key(),
        client=ipfs_backend.client,
    )
    reloaded.load_checkpoint()
    assert reloaded._file_index == {}
