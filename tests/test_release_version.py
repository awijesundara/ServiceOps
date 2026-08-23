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
