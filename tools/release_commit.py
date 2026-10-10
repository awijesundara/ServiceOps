#!/usr/bin/env python3
"""Create the signed release commit and its signed annotated tag.

`main` requires verified signatures. A commit made with `git commit` inside
Actions is unsigned and is rejected, so the release commit is created with
GraphQL `createCommitOnBranch` instead: GitHub signs commits it creates for
the workflow token. The tag is created only after that commit has landed on
`main`, so a failed run can never leave a tag on a commit outside `main`.

GitHub does not sign tag objects created through its API, so the tag is made
with git and SSH-signed with the release signing key
(RELEASE_TAG_SIGNING_KEY, registered as a signing key on the tagger's GitHub
account so the tag shows as Verified), then pushed. The key is checked before
anything is created: without it the release stops instead of tagging unsigned.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

RELEASE_FILES = {
    "VERSION", "README.md", "charts/serviceops/Chart.yaml", "charts/serviceops/values.yaml",
    "static/service-worker.js", ".env.example", "installer/app.py", "tools/install/server.sh",
    "packaging/rpm/serviceops.spec",
}

CREATE_COMMIT = """
mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid } }
}
"""


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout.strip()


TAGGER_NAME = "Anushka Wijesundara"
TAGGER_EMAIL = "anushka@wijesundara.com"


def api(method: str, path: str, payload: dict | None = None) -> dict:
    request = urllib.request.Request(
        os.environ.get("GITHUB_API_URL", "https://api.github.com") + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={
            "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def changed_release_files() -> list[str]:
    changed = [path for path in git("diff", "--name-only").splitlines() if path]
    unexpected = sorted(set(changed) - RELEASE_FILES)
    if unexpected:
        raise SystemExit(f"Refusing to release unexpected changes: {', '.join(unexpected)}")
    if "VERSION" not in changed:
        raise SystemExit("VERSION is unchanged; nothing to release")
    return sorted(changed)


def signing_key() -> str:
    key = os.environ.get("RELEASE_TAG_SIGNING_KEY", "").strip()
    if "PRIVATE KEY" not in key:
        raise SystemExit("RELEASE_TAG_SIGNING_KEY is not set; refusing to create an unsigned release tag")
    return key + "\n"


def push_signed_tag(tag: str, commit: str, key: str) -> None:
    git("fetch", "--no-tags", "origin", commit)
    with tempfile.TemporaryDirectory() as workdir:
        key_path = os.path.join(workdir, "release-signing-key")
        with open(os.open(key_path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as handle:
            handle.write(key)
        git(
            "-c", f"user.name={TAGGER_NAME}", "-c", f"user.email={TAGGER_EMAIL}",
            "-c", "gpg.format=ssh", "-c", f"user.signingkey={key_path}",
            "tag", "-s", "-m", f"ServiceOps {tag}", tag, commit,
        )
    git("push", "origin", f"refs/tags/{tag}")


def tag_is_verified(tag: str, repository: str, attempts: int = 6) -> bool:
    for attempt in range(attempts):
        ref = api("GET", f"/repos/{repository}/git/ref/tags/{tag}")
        tag_object = api("GET", f"/repos/{repository}/git/tags/{ref['object']['sha']}")
        if tag_object.get("verification", {}).get("verified"):
            return True
        time.sleep(5 * (attempt + 1))
    return False


def release(tag: str, repository: str, branch: str = "main") -> str:
    version = tag.removeprefix("v")
    key = signing_key()
    head = git("rev-parse", "HEAD")
    additions = []
    for path in changed_release_files():
        with open(path, "rb") as handle:
            additions.append({"path": path, "contents": base64.b64encode(handle.read()).decode()})
    result = api("POST", "/graphql", {"query": CREATE_COMMIT, "variables": {"input": {
        "branch": {"repositoryNameWithOwner": repository, "branchName": branch},
        "message": {"headline": f"chore(release): {version}"},
        "expectedHeadOid": head,
        "fileChanges": {"additions": additions},
    }}})
    if result.get("errors"):
        raise SystemExit(f"Release commit was not created: {result['errors']}")
    commit = result["data"]["createCommitOnBranch"]["commit"]["oid"]
    push_signed_tag(tag, commit, key)
    if not tag_is_verified(tag, repository):
        raise SystemExit(f"{tag} was pushed but GitHub does not report its signature as verified")
    return commit


if __name__ == "__main__":
    print(release(sys.argv[1], os.environ["GITHUB_REPOSITORY"]))
