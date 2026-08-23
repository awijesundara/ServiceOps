#!/usr/bin/env python3
"""Calculate, apply, and verify one ServiceOps semantic release version."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
    current_version = (ROOT / "VERSION").read_text().strip()
    chart = ROOT / "charts/serviceops/Chart.yaml"
    readme = ROOT / "README.md"
    rpm_spec = ROOT / "packaging/rpm/serviceops.spec"
    worker = ROOT / "static/service-worker.js"
    env_example = ROOT / ".env.example"
    installer = ROOT / "installer/app.py"
    server_installer = ROOT / "tools/install/server.sh"
    chart_values = ROOT / "charts/serviceops/values.yaml"
    return {
        ROOT / "VERSION": version + "\n",
        chart: re.sub(
            r'(?m)^(version: ).*$|^(appVersion: ).*$',
            lambda match: f"version: {version}" if match.group(1) else f'appVersion: "{version}"',
            chart.read_text(),
        ),
        # Installation commands and release links intentionally include the
        # current version. Advancing only the badge would leave unsafe,
        # copy-pasteable instructions pointing at an older package.
        readme: readme.read_text().replace(current_version, version),
        worker: re.sub(
            r"(\?v=)[0-9]+\.[0-9]+\.[0-9]+",
            rf"\g<1>{version}",
            re.sub(r'(?m)^const CACHE_NAME = .*$', f'const CACHE_NAME = "serviceops-shell-v{version}";', worker.read_text()),
        ),
        env_example: re.sub(
            r"(?m)^(SERVICEOPS_IMAGE=serviceops-app:)[0-9]+\.[0-9]+\.[0-9]+$",
            rf"\g<1>{version}",
            env_example.read_text(),
        ),
        installer: re.sub(
            r'("serviceops-app:)[0-9]+\.[0-9]+\.[0-9]+(")',
            rf"\g<1>{version}\g<2>",
            installer.read_text(),
        ),
        server_installer: re.sub(
            r"(SERVICEOPS_IMAGE=serviceops-app:)[0-9]+\.[0-9]+\.[0-9]+",
            rf"\g<1>{version}",
            server_installer.read_text(),
        ),
        chart_values: re.sub(
            r'(?m)^(  tag: ")[0-9]+\.[0-9]+\.[0-9]+(")$',
            rf"\g<1>{version}\g<2>",
            chart_values.read_text(),
        ),
        rpm_spec: synchronized_rpm_changelog(rpm_spec.read_text(), current_version, version),
    }


def synchronized_rpm_changelog(content: str, current_version: str, version: str) -> str:
    if version == current_version:
        return content
    release_date = datetime.now(timezone.utc).strftime("%a %b %d %Y")
    entry = (
        f"* {release_date} ServiceOps Maintainer <serviceops-maintainer@users.noreply.github.com> - {version}-1\n"
        "- Publish governed release artifacts with synchronized installation documentation.\n\n"
    )
    return content.replace("%changelog\n", "%changelog\n" + entry, 1)


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
