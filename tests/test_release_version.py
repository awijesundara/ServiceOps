from pathlib import Path
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
