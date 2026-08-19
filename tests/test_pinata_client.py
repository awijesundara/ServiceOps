"""Unit tests for serviceops_core/storage/pinata_client.py -- the free
hosted-pinning-service alternative to a self-hosted Kubo node under
STORAGE_MODE=ipfs, IPFS_PROVIDER=pinata. No real Pinata account is used:
a fake httpx-compatible session records calls and returns canned
httpx.Response objects, matching this repo's existing pattern of testing
the IPFS backend against a fake node rather than a live one (see
tests/test_storage_backend.py's FakeIPFSClient / test_ipfs_backend_live.py
split).
"""
import httpx
import pytest

from serviceops_core.storage.ipfs_backend import IPFSStorageBackend
from serviceops_core.storage.pinata_client import PinataClientError, PinataIPFSClient
from cryptography.fernet import Fernet


class FakeSession:
    """Records every call and serves canned responses keyed by (method, url)
    prefix, in the order they were registered -- enough to drive
    PinataIPFSClient's real request-shaping logic without the network."""

    def __init__(self):
        self.calls = []
        self._responses = {}

    def queue(self, method, url_prefix, response):
        self._responses.setdefault((method, url_prefix), []).append(response)

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for (m, prefix), queue in self._responses.items():
            if m == method and url.startswith(prefix) and queue:
                response = queue.pop(0)
                response._request = httpx.Request(method, url)
                return response
        raise AssertionError(f"No fake response queued for {method} {url}")


def test_missing_jwt_raises_clear_error():
    with pytest.raises(PinataClientError, match="PINATA_JWT"):
        PinataIPFSClient(jwt="")


def test_add_bytes_uploads_and_returns_cid():
    session = FakeSession()
    session.queue(
        "POST", PinataIPFSClient.upload_api,
        httpx.Response(200, json={"data": {"cid": "bafy-uploaded"}}),
    )
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    cid = client.add_bytes(b"hello world", filename="myfile")
    assert cid == "bafy-uploaded"
    method, url, kwargs = session.calls[0]
    assert kwargs["headers"]["Authorization"] == "Bearer test-jwt"
    assert kwargs["files"]["file"] == ("myfile", b"hello world")


def test_cat_fetches_from_public_gateway():
    session = FakeSession()
    session.queue("GET", f"{PinataIPFSClient.default_gateway}/bafy-1", httpx.Response(200, content=b"payload bytes"))
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    assert client.cat("bafy-1") == b"payload bytes"


def test_cat_falls_back_to_a_signed_private_download_link_on_403():
    # Found via live testing: this API's uploads land on Pinata's private
    # IPFS network by default, so the plain gateway path 403s and a
    # signed, short-lived download link must be used instead.
    session = FakeSession()
    session.queue("GET", f"{PinataIPFSClient.default_gateway}/bafy-private", httpx.Response(403))
    session.queue(
        "POST", "https://api.pinata.cloud/v3/files/private/download_link",
        httpx.Response(200, json={"data": "https://gateway.pinata.cloud/files/bafy-private?X-Signature=abc"}),
    )
    session.queue(
        "GET", "https://gateway.pinata.cloud/files/bafy-private?X-Signature=abc",
        httpx.Response(200, content=b"private payload"),
    )
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    assert client.cat("bafy-private") == b"private payload"


def test_401_response_raises_clear_error():
    session = FakeSession()
    session.queue("POST", PinataIPFSClient.upload_api, httpx.Response(401))
    client = PinataIPFSClient(jwt="bad-jwt", session=session)
    with pytest.raises(PinataClientError, match="Invalid Pinata JWT"):
        client.add_bytes(b"x")


def test_name_publish_uploads_pointer_and_deletes_old_versions():
    session = FakeSession()
    # First publish: no existing pointer file.
    session.queue("GET", PinataIPFSClient.list_api, httpx.Response(200, json={"data": {"files": []}}))
    session.queue(
        "POST", PinataIPFSClient.upload_api,
        httpx.Response(200, json={"data": {"cid": "bafy-pointer-1"}}),
    )
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    client.name_publish("bafy-checkpoint-1", "serviceops-checkpoint")
    upload_call = [c for c in session.calls if c[0] == "POST"][0]
    assert upload_call[2]["files"]["file"] == ("serviceops-checkpoint-pointer", b"bafy-checkpoint-1")

    # Second publish: one old pointer file exists and must be deleted.
    session.queue(
        "GET", PinataIPFSClient.list_api,
        httpx.Response(200, json={"data": {"files": [{"id": "file-1", "cid": "bafy-pointer-1"}]}}),
    )
    session.queue(
        "POST", PinataIPFSClient.upload_api,
        httpx.Response(200, json={"data": {"cid": "bafy-pointer-2"}}),
    )
    session.queue("DELETE", f"{PinataIPFSClient.list_api}/file-1", httpx.Response(200))
    client.name_publish("bafy-checkpoint-2", "serviceops-checkpoint")
    assert ("DELETE", f"{PinataIPFSClient.list_api}/file-1", {"headers": {"Authorization": "Bearer test-jwt"}}) in [
        (m, u, {"headers": k["headers"]}) for m, u, k in session.calls
    ]


def test_name_resolve_returns_none_when_no_pointer_exists():
    session = FakeSession()
    session.queue("GET", PinataIPFSClient.list_api, httpx.Response(200, json={"data": {"files": []}}))
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    assert client.name_resolve("serviceops-checkpoint") is None


def test_name_resolve_fetches_pointer_content_as_the_cid():
    session = FakeSession()
    session.queue(
        "GET", PinataIPFSClient.list_api,
        httpx.Response(200, json={"data": {"files": [{"id": "file-9", "cid": "bafy-pointer-9"}]}}),
    )
    session.queue(
        "GET", f"{PinataIPFSClient.default_gateway}/bafy-pointer-9",
        httpx.Response(200, content=b"bafy-actual-checkpoint-cid"),
    )
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    assert client.name_resolve("serviceops-checkpoint") == "bafy-actual-checkpoint-cid"


def test_node_id_uses_test_authentication_endpoint():
    session = FakeSession()
    session.queue(
        "GET", "https://api.pinata.cloud/data/testAuthentication",
        httpx.Response(200, json={"message": "Congratulations! You are communicating with the Pinata API!"}),
    )
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    assert "Congratulations" in client.node_id()


def test_custom_gateway_overrides_the_shared_default():
    session = FakeSession()
    session.queue("GET", "https://my-name.mypinata.cloud/ipfs/bafy-1", httpx.Response(200, content=b"payload"))
    client = PinataIPFSClient(jwt="test-jwt", session=session, gateway="https://my-name.mypinata.cloud/ipfs")
    assert client.cat("bafy-1") == b"payload"


def test_key_gen_returns_name_verbatim():
    client = PinataIPFSClient(jwt="test-jwt", session=FakeSession())
    assert client.key_gen("serviceops-checkpoint") == "serviceops-checkpoint"


def test_pin_add_is_a_noop():
    client = PinataIPFSClient(jwt="test-jwt", session=FakeSession())
    assert client.pin_add("bafy-1") is None


# -- IPFSStorageBackend wired to a real (fake-session) PinataIPFSClient ----

def test_ipfs_storage_backend_boots_and_writes_through_pinata_client():
    session = FakeSession()
    # load_checkpoint(): key_gen is a no-op, name_resolve finds nothing yet.
    session.queue("GET", PinataIPFSClient.list_api, httpx.Response(200, json={"data": {"files": []}}))
    client = PinataIPFSClient(jwt="test-jwt", session=session)
    backend = IPFSStorageBackend(api_url=None, checkpoint_encryption_key=Fernet.generate_key(), client=client)
    backend.load_checkpoint()

    # attach_file(): add_bytes (upload), then save_checkpoint()'s add_bytes
    # (checkpoint upload) + name_publish (list old pointers, upload new one).
    session.queue("POST", PinataIPFSClient.upload_api, httpx.Response(200, json={"data": {"cid": "bafy-file"}}))
    session.queue("POST", PinataIPFSClient.upload_api, httpx.Response(200, json={"data": {"cid": "bafy-checkpoint"}}))
    session.queue("GET", PinataIPFSClient.list_api, httpx.Response(200, json={"data": {"files": []}}))
    session.queue("POST", PinataIPFSClient.upload_api, httpx.Response(200, json={"data": {"cid": "bafy-pointer"}}))

    cid = backend.attach_file("report.pdf", b"secret bytes", "application/pdf")
    assert cid == "bafy-file"
