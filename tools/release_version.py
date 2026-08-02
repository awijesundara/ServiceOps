#!/usr/bin/env python3
"""Calculate, apply, and verify one ServiceOps semantic release version."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def parse(value: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value.strip())
    if not match:
        raise ValueError(f"Invalid semantic version: {value!r}")
    return tuple(map(int, match.groups()))


def next_version(current: tuple[int, int, int], part: str) -> tuple[int, int, int]:
    major, minor, patch = current
    if part == "major":
        return major + 1, 0, 0
    if part == "minor":
        return major, minor + 1, 0
    return major, minor, patch + 1


def render(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def synchronized_content(version: str) -> dict[Path, str]:
    chart = ROOT / "charts/serviceops/Chart.yaml"
    readme = ROOT / "README.md"
    worker = ROOT / "static/service-worker.js"
    return {
        ROOT / "VERSION": version + "\n",
        chart: re.sub(
            r'(?m)^(version: ).*$|^(appVersion: ).*$',
            lambda match: f"version: {version}" if match.group(1) else f'appVersion: "{version}"',
            chart.read_text(),
        ),
        readme: re.sub(
            r"version-[0-9]+\.[0-9]+\.[0-9]+-003E4C",
            f"version-{version}-003E4C",
            readme.read_text(),
        ),
        worker: re.sub(
            r"(\?v=)[0-9]+\.[0-9]+\.[0-9]+",
            rf"\g<1>{version}",
            re.sub(r'(?m)^const CACHE_NAME = .*$', f'const CACHE_NAME = "serviceops-shell-v{version}";', worker.read_text()),
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--bump", choices=("major", "minor", "patch"))
    target.add_argument("--set", dest="set_version")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    current = parse((ROOT / "VERSION").read_text())
    selected = (
        parse(args.set_version.removeprefix("v"))
        if args.set_version
        else next_version(current, args.bump) if args.bump else current
    )
    version = render(selected)
    files = synchronized_content(version)
    if args.write:
        for path, content in files.items():
            path.write_text(content)
    if args.check:
        mismatches = [str(path.relative_to(ROOT)) for path, content in files.items() if path.read_text() != content]
        if mismatches:
            raise SystemExit("Version drift: " + ", ".join(mismatches))
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
