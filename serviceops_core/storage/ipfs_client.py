"""Minimal HTTP client for Kubo's RPC API (the reference IPFS
implementation). Deliberately small and dependency-light -- built on
httpx, already a ServiceOps dependency, rather than adding a new
ipfshttpclient/py-ipfs-http-client package for a handful of calls.

Every method raises httpx.HTTPError (or a subclass) on a non-2xx
response; callers decide how to handle an unreachable/misbehaving node --
this module has no retry/fallback policy of its own.
"""
import httpx


class IPFSClientError(RuntimeError):
    """Raised for IPFS RPC responses that are 2xx but semantically wrong
    (e.g. a key-generation collision the caller should treat as OK)."""


class IPFSClient:
    # Found via live testing (BACKLOG B-335): name/publish can
    # intermittently hang well past the RPC's usual sub-second response
    # time even with allow-offline=true. 30s meant a slow publish held a
    # whole request (e.g. a failed login attempt) open that long before
    # IPFSStorageBackend.save_checkpoint() catches and logs the failure --
    # 12s bounds the damage without being so tight it flags normal
    # variance as a hard failure.
    def __init__(self, api_url, timeout=12.0):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def _post(self, path, params=None, files=None):
        response = httpx.post(
            f"{self.api_url}{path}", params=params, files=files, timeout=self.timeout,
        )
        response.raise_for_status()
        return response

    def add_bytes(self, data_bytes, filename="blob"):
        """Add content to IPFS (not pinned by this call alone -- Kubo pins
        by default on `add` unless configured otherwise; callers that need
        a guarantee should follow up with pin_add)."""
        response = self._post("/api/v0/add", files={"file": (filename, data_bytes)})
        return response.json()["Hash"]

    def cat(self, cid):
        response = self._post("/api/v0/cat", params={"arg": cid})
        return response.content

    def pin_add(self, cid):
        self._post("/api/v0/pin/add", params={"arg": cid})

    def pin_rm(self, cid):
        try:
            self._post("/api/v0/pin/rm", params={"arg": cid})
        except httpx.HTTPStatusError:
            # Already unpinned, or never pinned -- not an error for our
            # purposes (mirrors PostgresStorageBackend.delete_file's
            # best-effort FileNotFoundError swallow).
            pass

    def key_list(self):
        response = self._post("/api/v0/key/list")
        return {row["Name"]: row["Id"] for row in response.json().get("Keys", [])}

    def key_gen(self, name):
        existing = self.key_list()
        if name in existing:
            return existing[name]
        response = self._post("/api/v0/key/gen", params={"arg": name, "type": "ed25519"})
        return response.json()["Id"]

    def name_publish(self, cid, key_name):
        # allow-offline=true is required: found via real testing -- without
        # it, Kubo's default IPNS publish tries to provide the record to
        # the public DHT and can hang for 30s+ (our request timeout) on a
        # node with few/no swarm peers, which every "bundled" (single,
        # private, self-hosted) IPFS node is by design. The checkpoint
        # pointer only ever needs to be resolved by this same app talking
        # to this same local node, not discovered by the wider public
        # network, so skipping DHT provide is the correct choice here, not
        # just a workaround.
        self._post(
            "/api/v0/name/publish",
            params={"arg": f"/ipfs/{cid}", "key": key_name, "allow-offline": "true"},
        )

    def name_resolve(self, name_or_peer_id):
        # nocache=true is required: found via real testing against a live
        # Kubo node (not theorized) -- Kubo caches resolved IPNS results by
        # default (config Ipns.ResolveCacheSize), so a resolve immediately
        # after this same process's own name_publish() can return a stale
        # CID from before the publish, even tens of seconds later. Since
        # IPFSStorageBackend.load_checkpoint() needs the *current* head on
        # every boot, correctness requires bypassing that cache here.
        try:
            response = self._post(
                "/api/v0/name/resolve",
                params={"arg": f"/ipns/{name_or_peer_id}", "nocache": "true"},
            )
        except httpx.HTTPStatusError:
            return None
        path = response.json().get("Path", "")
        return path.removeprefix("/ipfs/") if path.startswith("/ipfs/") else None

    def node_id(self):
        response = self._post("/api/v0/id")
        return response.json()["ID"]
