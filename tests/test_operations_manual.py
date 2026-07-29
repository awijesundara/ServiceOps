"""Guards the operations manual against silent drift: every screenshot the
Markdown source references must actually exist, so a renamed/removed capture
doesn't quietly disappear from the generated PDF (the generator only prints a
warning and skips it — it doesn't fail the build)."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IMAGE_RE = re.compile(r"!\[.*?\]\((.*?)\)")


def test_all_referenced_screenshots_exist():
    if not (ROOT / "docs" / "screenshots").is_dir():
        # docs/screenshots is deliberately excluded from Docker build contexts
        # via .dockerignore (it's a dev-only doc-generation asset, not needed
        # to run or test the application) — both Dockerfile and Dockerfile.test
        # share that exclusion, so a container-built test image never has it.
        # Absence here means "not shipped to this environment", not "missing".
        pytest.skip("docs/screenshots not present in this build context (see .dockerignore)")
    manual = (ROOT / "docs" / "OPERATIONS_MANUAL.md").read_text()
    refs = IMAGE_RE.findall(manual)
    assert refs, "expected the manual to reference at least one screenshot"
    missing = [ref for ref in refs if not (ROOT / "docs" / ref).exists()]
    assert not missing, f"OPERATIONS_MANUAL.md references screenshots that don't exist: {missing}"


def test_no_duplicate_screenshot_references():
    manual = (ROOT / "docs" / "OPERATIONS_MANUAL.md").read_text()
    refs = IMAGE_RE.findall(manual)
    seen = set()
    duplicates = {ref for ref in refs if ref in seen or seen.add(ref)}
    assert not duplicates, f"same screenshot embedded more than once: {duplicates}"
