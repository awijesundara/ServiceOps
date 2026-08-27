from pathlib import Path
import re
import subprocess
import sys


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


def test_readme_release_links_and_rpm_commands_use_canonical_version():
    version = (ROOT / "VERSION").read_text().strip()
    readme = (ROOT / "README.md").read_text()
    referenced_versions = set(re.findall(r"(?:/v|serviceops-|version-)(\d+\.\d+\.\d+)", readme))
    assert referenced_versions == {version}


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
