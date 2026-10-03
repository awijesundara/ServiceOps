#!/usr/bin/env python3
"""Create the release commit and its annotated tag through the GitHub API.

`main` requires verified signatures. A commit made with `git commit` inside
Actions is unsigned and is rejected, so the release commit is created with
GraphQL `createCommitOnBranch` instead: GitHub signs commits it creates for
the workflow token. The tag is created only after that commit has landed on
`main`, so a failed run can never leave a tag on a commit outside `main`.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
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


def api(method: str, path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        os.environ.get("GITHUB_API_URL", "https://api.github.com") + path,
        data=json.dumps(payload).encode(),
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


def release(tag: str, repository: str, branch: str = "main") -> str:
    version = tag.removeprefix("v")
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
    tag_object = api("POST", f"/repos/{repository}/git/tags", {
        "tag": tag, "message": f"ServiceOps {tag}", "object": commit, "type": "commit",
    })
    api("POST", f"/repos/{repository}/git/refs", {"ref": f"refs/tags/{tag}", "sha": tag_object["sha"]})
    return commit


if __name__ == "__main__":
    print(release(sys.argv[1], os.environ["GITHUB_REPOSITORY"]))
