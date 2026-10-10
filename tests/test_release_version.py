from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_semantic_and_synchronized():
    parts = (ROOT / "VERSION").read_text().strip().split(".")
    assert len(parts) == 3 and all(part.isdigit() for part in parts)
    subprocess.run(
        [sys.executable, "tools/release_version.py", "--check"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def test_application_reads_canonical_version():
    assert 'APP_VERSION = (Path(__file__).resolve().parent / "VERSION").read_text().strip()' in (ROOT / "app.py").read_text()


def test_readme_release_links_and_rpm_commands_use_one_published_version():
    """Local acceptance versions may intentionally precede GitHub publication.

    The README must never claim that an unpublished local build is available
    from GitHub, but every link and command for the published release must
    still agree on one semantic version.
    """
    readme = (ROOT / "README.md").read_text()
    referenced_versions = set(re.findall(r"(?:/v|serviceops-|version-)(\d+\.\d+\.\d+)", readme))
    assert len(referenced_versions) == 1
    assert all(len(value.split(".")) == 3 for value in referenced_versions)


def test_governed_release_packages_the_immutable_release_tag():
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text()
    rpm_workflow = (ROOT / ".github/workflows/rpm.yml").read_text()
    assert "checkout_ref: ${{ needs.version.outputs.tag }}" in release_workflow
    assert "ref: ${{ inputs.checkout_ref || github.ref }}" in rpm_workflow
    assert 'sha256sum "$rpm_name" > "$rpm_name.sha256"' in rpm_workflow
    assert 'printf \'%s  %s\\n\' "$actual" "${rpm#./}" > "$checksum"' in release_workflow


def test_successful_main_gate_automatically_enters_governed_release_pipeline():
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert 'workflow_run:' in release_workflow
    assert 'workflows: ["ServiceOps supply-chain gate"]' in release_workflow
    assert "github.event.workflow_run.conclusion == 'success'" in release_workflow
    assert "github.event.workflow_run.head_branch == 'main'" in release_workflow
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in release_workflow
    assert "!startsWith(github.event.workflow_run.head_commit.message, 'chore(release):')" in release_workflow
    assert 'test "$(git rev-parse HEAD)" = "$VALIDATED_SHA"' in release_workflow
    assert "INCREMENT: ${{ inputs.increment || 'patch' }}" in release_workflow
    assert "cancel-in-progress: false" in release_workflow


def test_supply_chain_checkout_keeps_parent_for_migration_policy():
    supply_chain = (ROOT / ".github/workflows/supply-chain.yml").read_text()
    assert "python tools/verify_migration_safety.py --changed-against HEAD^" in supply_chain
    assert "fetch-depth: 2" in supply_chain


def test_no_stale_serviceops_image_versions_outside_release_managed_files():
    version = (ROOT / "VERSION").read_text().strip()
    for relative_path in (
        ".env.example",
        "installer/app.py",
        "tools/install/server.sh",
        "charts/serviceops/values.yaml",
    ):
        content = (ROOT / relative_path).read_text()
        assert f"serviceops-app:{version}" in content or f'tag: "{version}"' in content


def test_read_only_runtime_disables_gunicorn_control_socket():
    entrypoint = (ROOT / "tools/gunicorn-entrypoint.sh").read_text()
    assert "--no-control-socket" in entrypoint


def test_offline_bundle_is_fail_closed_and_immutable():
    vendorize = (ROOT / "tools/offline/vendorize.sh").read_text()
    loader = (ROOT / "tools/offline/build-offline.sh").read_text()
    images = (ROOT / "tools/offline/docker-images.txt").read_text().splitlines()
    assert "SERVICEOPS_IMAGE must be an immutable" in vendorize
    assert "sha256sum --check SHA256SUMS" in vendorize
    assert "sha256sum --check SHA256SUMS" in loader
    assert "Unsafe archive path" in loader
    assert all("@sha256:" in line for line in images if line and not line.startswith("#"))


def test_developer_and_ci_commands_never_suppress_failures():
    makefile = (ROOT / "Makefile").read_text()
    workflows = "\n".join(path.read_text() for path in (ROOT / ".github/workflows").glob("*.yml"))
    assert "|| true" not in makefile
    assert "pytest -q || true" not in workflows


FAKE_SIGNING_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"


def load_release_commit():
    import sys

    sys.path.insert(0, str(ROOT / "tools"))
    import release_commit
    return release_commit


def test_release_commit_is_created_by_the_api_and_signed_tag_pushed_after_it_lands(monkeypatch, tmp_path):
    release_commit = load_release_commit()
    calls, git_calls = [], []

    def fake_api(method, path, payload=None):
        calls.append((method, path, payload))
        if path == "/graphql":
            return {"data": {"createCommitOnBranch": {"commit": {"oid": "c0ffee"}}}}
        if "/git/ref/tags/" in path:
            return {"object": {"sha": "7a9"}}
        if path.endswith("/git/tags/7a9"):
            return {"verification": {"verified": True, "reason": "valid"}}
        raise AssertionError(path)

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "diff":
            return "VERSION"
        if args[-2:] == ("v1.110.0", "c0ffee"):
            key_arg = next(a for a in args if a.startswith("user.signingkey="))
            assert open(key_arg.split("=", 1)[1]).read().startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
        return "abc123"

    (tmp_path / "VERSION").write_text("1.110.0\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RELEASE_TAG_SIGNING_KEY", FAKE_SIGNING_KEY)
    monkeypatch.setattr(release_commit, "api", fake_api)
    monkeypatch.setattr(release_commit, "git", fake_git)
    assert release_commit.release("v1.110.0", "owner/ServiceOps") == "c0ffee"

    commit_input = calls[0][2]["variables"]["input"]
    assert calls[0][1] == "/graphql" and commit_input["expectedHeadOid"] == "abc123"
    assert commit_input["message"]["headline"] == "chore(release): 1.110.0"
    assert [item["path"] for item in commit_input["fileChanges"]["additions"]] == ["VERSION"]
    assert not any(path.endswith("/git/tags") or path.endswith("/git/refs") for _, path, _ in calls)
    tag_call = next(args for args in git_calls if "tag" in args)
    assert "-s" in tag_call and "gpg.format=ssh" in tag_call
    assert "user.email=anushka@wijesundara.com" in tag_call
    assert ("push", "origin", "refs/tags/v1.110.0") in git_calls


def test_release_refuses_to_start_without_the_tag_signing_key(monkeypatch):
    release_commit = load_release_commit()
    monkeypatch.delenv("RELEASE_TAG_SIGNING_KEY", raising=False)
    monkeypatch.setattr(release_commit, "api", lambda *a, **k: pytest.fail("nothing may be created"))
    monkeypatch.setattr(release_commit, "git", lambda *a: pytest.fail("nothing may be created"))
    with pytest.raises(SystemExit, match="refusing to create an unsigned release tag"):
        release_commit.release("v1.110.0", "owner/ServiceOps")


def test_release_fails_when_github_does_not_verify_the_tag(monkeypatch):
    release_commit = load_release_commit()
    monkeypatch.setattr(release_commit.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(release_commit, "api", lambda method, path, payload=None: (
        {"object": {"sha": "7a9"}} if "/git/ref/" in path else {"verification": {"verified": False}}
    ))
    assert release_commit.tag_is_verified("v1.110.0", "owner/ServiceOps", attempts=2) is False


def test_release_commit_refuses_unexpected_changes(monkeypatch):
    release_commit = load_release_commit()

    monkeypatch.setattr(release_commit, "git", lambda *args: "VERSION\napp.py")
    with pytest.raises(SystemExit, match="unexpected changes: app.py"):
        release_commit.changed_release_files()


def test_release_workflow_signs_through_the_api_and_skips_taken_tags():
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert 'run: python3 tools/release_commit.py "$TAG"' in release_workflow
    assert "RELEASE_TAG_SIGNING_KEY: ${{ secrets.RELEASE_TAG_SIGNING_KEY }}" in release_workflow
    assert "git push origin HEAD:main" not in release_workflow
    assert 'while git rev-parse -q --verify "refs/tags/v${version}"' in release_workflow
