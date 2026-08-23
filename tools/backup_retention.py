#!/usr/bin/env python3
"""Prune complete ServiceOps recovery sets while retaining a safe minimum."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def recovery_sets(root: Path) -> list[tuple[float, list[Path]]]:
    sets: list[tuple[float, list[Path]]] = []
    for manifest in root.glob("serviceops-*.manifest.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            database = root / Path(data["database"]["name"]).name
            uploads = root / Path(data["uploads"]["name"]).name
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            # Never delete an incomplete or unparseable recovery set automatically.
            continue
        if database.is_file() and uploads.is_file():
            sets.append((manifest.stat().st_mtime, [manifest, database, uploads]))
    return sorted(sets, key=lambda item: item[0], reverse=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--minimum-sets", type=int, default=7)
    args = parser.parse_args()
    if args.days < 1 or args.minimum_sets < 1:
        parser.error("retention days and minimum sets must both be positive")

    cutoff = time.time() - args.days * 86400
    removed = 0
    for index, (created, members) in enumerate(recovery_sets(args.directory)):
        if index < args.minimum_sets or created >= cutoff:
            continue
        for member in members:
            member.unlink()
        removed += 1
    print(f"Backup retention complete: removed {removed} expired recovery set(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
