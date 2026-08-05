"""docs/API_REFERENCE.md is a byte-identical mirror of the maintained
original in the sibling serviceops-notes repo (see CLAUDE.md's
"Documentation control" section) -- the one deliberate public carve-out from
that repo's otherwise-private docs. This only checks the mirror when the
sibling repo is actually present on disk (it never is inside the isolated
Dockerfile.test build context, which only has this repo's own source), so it
enforces sync on a real dev machine / CI checkout without failing the
container test run for an unrelated reason.
"""
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MIRROR = REPO_ROOT / "docs" / "API_REFERENCE.md"
NOTES_REPO = Path(os.environ.get("SERVICEOPS_NOTES_REPO", REPO_ROOT.parent / "serviceops-notes"))
ORIGINAL = NOTES_REPO / "docs" / "API_REFERENCE.md"


@pytest.mark.skipif(not ORIGINAL.exists(), reason="sibling serviceops-notes checkout not present")
def test_api_reference_mirror_matches_maintained_original():
    assert MIRROR.exists(), "docs/API_REFERENCE.md is missing from the public repo"
    assert MIRROR.read_text() == ORIGINAL.read_text(), (
        "docs/API_REFERENCE.md has drifted from serviceops-notes/docs/API_REFERENCE.md -- "
        "re-run serviceops-notes/tools/sync_api_reference.sh"
    )
