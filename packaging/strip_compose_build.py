#!/usr/bin/env python3
"""Remove the `build:` stanza from a ServiceOps compose file for distribution.

Packaged installs (RPM, etc.) ship no application source or Dockerfile on the
host -- only a pinned registry image reference. Compose's `build:` block is
meaningless there and `docker compose up --build` would fail outright, so the
distributed copy of each compose file must reference `image:` only.

Each service's build stanza is a fixed five-line block:
    build:
      context: .
      args:
        PIP_INDEX_URL: ${PIP_INDEX_URL:-}
        PIP_TRUSTED_HOST: ${PIP_TRUSTED_HOST:-}
This intentionally fails loudly (rather than silently no-op) if that shape
ever changes, so packaging breakage is caught at build time, not at a
customer's install time.
"""
import sys

BLOCK = [
    "    build:\n",
    "      context: .\n",
    "      args:\n",
    "        PIP_INDEX_URL: ${PIP_INDEX_URL:-}\n",
    "        PIP_TRUSTED_HOST: ${PIP_TRUSTED_HOST:-}\n",
]


def strip(path):
    lines = open(path, encoding="utf-8").readlines()
    out = []
    i = 0
    removed = 0
    while i < len(lines):
        if lines[i : i + len(BLOCK)] == BLOCK:
            i += len(BLOCK)
            removed += 1
            continue
        out.append(lines[i])
        i += 1
    if removed == 0:
        raise SystemExit(f"{path}: expected build: stanza not found; refusing to write an unchanged file.")
    open(path, "w", encoding="utf-8").writelines(out)
    print(f"{path}: removed {removed} build: stanza(s)")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        strip(arg)
