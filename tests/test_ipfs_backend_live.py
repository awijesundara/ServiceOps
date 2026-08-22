"""Real-infrastructure verification for IPFSStorageBackend against an
actual Kubo node -- not mocked, per this repo's "build and test against
real dependencies" standard. Skipped unless IPFS_LIVE_TEST_API_URL points
at a real, disposable IPFS node (see the storage-mode plan's suggested
first slice). To run locally:

    docker run -d --rm -p 127.0.0.1:15001:5001 \\
        ipfs/kubo:v0.33.0@sha256:a11e89f0f2a620acb3e8e1c49cdce81e80115194681924a5356f301cc6b66067
    IPFS_LIVE_TEST_API_URL=http://127.0.0.1:15001 pytest tests/test_ipfs_backend_live.py

This suite is what actually caught two real bugs during development that
mocked tests could not have found: Kubo's name/resolve caches results by
default (a resolve immediately after this same process's own publish can
return a stale CID), and name/publish without allow-offline hangs for the
full request timeout on a node with no swarm peers, which every bundled/
single-node deployment has by design. Both are fixed in ipfs_client.py;
this suite guards against a regression reintroducing either.
"""
import os
import time

import pytest
from cryptography.fernet import Fernet

from serviceops_core.storage.ipfs_backend import IPFSStorageBackend

API_URL = os.environ.get("IPFS_LIVE_TEST_API_URL", "")

pytestmark = pytest.mark.skipif(
    not API_URL, reason="set IPFS_LIVE_TEST_API_URL to a real Kubo node to run this suite"
)


def wait_for_checkpoint_publication(backend, timeout=30):
    """Wait for the durability signal exposed by the async IPNS publisher."""
    deadline = time.monotonic() + timeout
    while backend.checkpoint_publish_pending and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not backend.checkpoint_publish_pending, "IPFS checkpoint publication did not complete"


def test_checkpoint_round_trips_through_a_real_restart():
    key = Fernet.generate_key()
    backend = IPFSStorageBackend(api_url=API_URL, checkpoint_encryption_key=key)
    backend.load_checkpoint()

    cid = backend.attach_file("live-test.txt", b"real ipfs data", "text/plain")
    data, _ = backend.read_file("live-test.txt", cid)
    assert data == b"real ipfs data"
    wait_for_checkpoint_publication(backend)

    # A brand-new backend instance (simulating a real process restart)
    # against the same node/key must see the write immediately, not after
    # some cache/propagation delay -- this is the exact case that caught
    # Kubo's default name/resolve caching during development.
    reloaded = IPFSStorageBackend(api_url=API_URL, checkpoint_encryption_key=key)
    reloaded.load_checkpoint()
    assert reloaded._file_index.get("live-test.txt") == cid
    data2, _ = reloaded.read_file("live-test.txt", None)
    assert data2 == b"real ipfs data"

    backend.delete_file("live-test.txt", cid)
    wait_for_checkpoint_publication(backend)
    reloaded2 = IPFSStorageBackend(api_url=API_URL, checkpoint_encryption_key=key)
    reloaded2.load_checkpoint()
    assert "live-test.txt" not in reloaded2._file_index


def test_publish_does_not_hang_on_a_node_with_no_swarm_peers():
    """Regression guard for the allow-offline fix: a bundled/single-node
    IPFS deployment has no DHT peers by design, and Kubo's default
    name/publish tries to provide to the DHT anyway -- this used to hang
    for the full request timeout (30s) before allow-offline=true was
    added. A single attach_file() call completing at all (within the
    client's normal timeout) is the regression signal."""
    key = Fernet.generate_key()
    backend = IPFSStorageBackend(api_url=API_URL, checkpoint_encryption_key=key)
    backend.load_checkpoint()
    backend.attach_file("timing.txt", b"data", "text/plain")
