"""HTTP client for Pinata's Files API v3 -- a free, hosted IPFS pinning
service, offered as an alternative to a self-hosted Kubo node for
STORAGE_MODE=ipfs deployments (IPFS_PROVIDER=pinata). This mirrors the
ServiceOps iOS app's PinataWorkspaceClient (see
XCode_Development/ServiceOps/ServiceOps/PinataWorkspaceClient.swift and
docs/ipfs-mode.md in that repo), adapted to satisfy the same client
surface as IPFSClient (serviceops_core/storage/ipfs_client.py) so it
drops straight into IPFSStorageBackend with no changes to that class.

Pinata has no IPNS-style mutable pointer, so the checkpoint pointer is
implemented the same way the iOS app implements its workspace documents:
a named file is the pointer -- the "latest" value is always the newest
file with a matching name (Pinata content is otherwise immutable; each
upload gets a new CID). Every publish therefore uploads a new pointer
file and deletes the previous ones, exactly like PinataWorkspaceClient's
writeDocument() -- both to converge on a single "latest" value and to
stay within the free tier's file-count limit.
"""
import time

import httpx


class PinataClientError(RuntimeError):
    """Raised for Pinata API responses that are 2xx but semantically
    wrong, and for authentication failures surfaced as a clear message."""


class PinataIPFSClient:
    list_api = "https://api.pinata.cloud/v3/files"
    upload_api = "https://uploads.pinata.cloud/v3/files"
    # Fallback only. Pinata's shared public gateway is unreliable in
    # practice (found via live testing: every request to it timed out
    # outright, even for content just uploaded through this same
    # account) -- every account gets its own free dedicated gateway
    # subdomain (e.g. https://<name>.mypinata.cloud/ipfs), which should
    # be configured explicitly via PINATA_GATEWAY_URL/the installer's
    # "Pinata gateway URL" field rather than relying on this default.
    default_gateway = "https://gateway.pinata.cloud/ipfs"

    def __init__(self, jwt, session=None, timeout=15.0, gateway=None):
        jwt = (jwt or "").strip()
        if not jwt:
            raise PinataClientError(
                "PINATA_JWT is required when IPFS_PROVIDER=pinata. Get a free "
                "JWT at pinata.cloud."
            )
        self.jwt = jwt
        self.timeout = timeout
        self._client = session or httpx
        self.gateway = (gateway or self.default_gateway).rstrip("/")

    def _headers(self):
        return {"Authorization": f"Bearer {self.jwt}"}

    def _request(self, method, url, **kwargs):
        try:
            response = self._client.request(
                method, url, timeout=self.timeout, headers=self._headers(), **kwargs
            )
        except httpx.HTTPError as exc:
            raise PinataClientError(f"Could not reach Pinata: {exc}") from exc
        if response.status_code == 401:
            raise PinataClientError("Invalid Pinata JWT (PINATA_JWT).")
        response.raise_for_status()
        return response

    # -- IPFSClient-compatible surface ------------------------------------
    def add_bytes(self, data_bytes, filename="blob"):
        response = self._request(
            "POST", self.upload_api,
            files={"file": (filename, data_bytes)},
            data={"name": filename},
        )
        return response.json()["data"]["cid"]

    def cat(self, cid):
        try:
            response = self._gateway_get(f"{self.gateway}/{cid}")
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 403:
                raise PinataClientError(f"Could not fetch {cid} from the Pinata gateway: {exc}") from exc
            # 403 on the plain /ipfs/<cid> path is expected, not an error:
            # found via live testing that this API's uploads land on
            # Pinata's private IPFS network by default, which the public
            # gateway path can't serve at all -- only a short-lived signed
            # link can. Confirmed live against a real dedicated gateway.
            response = self._gateway_get(self._sign_private_download_link(cid))
        except httpx.HTTPError as exc:
            raise PinataClientError(f"Could not fetch {cid} from the Pinata gateway: {exc}") from exc
        return response.content

    def _gateway_get(self, url):
        response = self._client.request("GET", url, timeout=self.timeout)
        response.raise_for_status()
        return response

    def _sign_private_download_link(self, cid):
        base = self.gateway.removesuffix("/ipfs")
        response = self._request(
            "POST", "https://api.pinata.cloud/v3/files/private/download_link",
            json={"url": f"{base}/files/{cid}", "expires": 3600,
                  "date": int(time.time()), "method": "GET"},
        )
        return response.json()["data"]

    def pin_add(self, cid):
        # Every upload through add_bytes() is pinned by Pinata automatically;
        # there is no separate pin step in the Files API v3.
        return None

    def pin_rm(self, cid):
        # Best-effort, mirrors IPFSClient.pin_rm()'s swallow-on-failure
        # contract. Deleting a Pinata file by CID requires finding its file
        # id first; a miss (already gone, or never tracked as a distinct
        # file -- e.g. shared content) is not an error for our purposes.
        try:
            response = self._request(
                "GET", self.list_api, params={"cid": cid, "pageLimit": 10},
            )
        except PinataClientError:
            return
        for file in response.json().get("data", {}).get("files", []):
            try:
                self._request("DELETE", f"{self.list_api}/{file['id']}")
            except PinataClientError:
                pass

    def key_gen(self, name):
        # No key-management concept in Pinata: the "key" is just the
        # pointer's file-name prefix, used verbatim by name_publish/resolve.
        return name

    def name_publish(self, cid, key_name):
        pointer_name = self._pointer_name(key_name)
        old = self._list_by_name(pointer_name, limit=20)
        self._request(
            "POST", self.upload_api,
            files={"file": (pointer_name, cid.encode("ascii"))},
            data={"name": pointer_name},
        )
        for file in old:
            try:
                self._request("DELETE", f"{self.list_api}/{file['id']}")
            except PinataClientError:
                pass

    def name_resolve(self, name_or_peer_id):
        pointer_name = self._pointer_name(name_or_peer_id)
        files = self._list_by_name(pointer_name, limit=1)
        if not files:
            return None
        try:
            return self.cat(files[0]["cid"]).decode("ascii").strip()
        except PinataClientError:
            return None

    def node_id(self):
        # Pinata has no node identity; the free-tier auth-check endpoint is
        # the closest equivalent of "this backend is reachable and the
        # credential is valid" for /health and /ready.
        response = self._request("GET", "https://api.pinata.cloud/data/testAuthentication")
        return response.json().get("message", "pinata")

    # -- internals ----------------------------------------------------------
    def _pointer_name(self, key_name):
        return f"{key_name}-pointer"

    def _list_by_name(self, name, limit):
        response = self._request(
            "GET", self.list_api,
            params={"name": name, "pageLimit": limit, "order": "DESC"},
        )
        return response.json().get("data", {}).get("files", [])
