"""Fail closed when a newly changed Alembic migration violates expand-contract policy."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations" / "versions"
POLICY = json.loads((ROOT / "config" / "migration_policy.json").read_text())


def changed_migrations(base: str) -> list[Path]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD", "--", "migrations/versions"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line.endswith(".py")]


def assignment(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    return None


def verify(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    phase = assignment(tree, "serviceops_migration_phase")
    errors = []
    if phase not in POLICY["allowed_phases"]:
        return [f"{path.name}: serviceops_migration_phase must be 'expand' or 'contract'"]
    source = path.read_text()
    if phase == "expand":
        for operation in POLICY["expand_forbidden_operations"]:
            if f"op.{operation}(" in source:
                errors.append(f"{path.name}: expand migration uses forbidden op.{operation}()")
    elif not assignment(tree, "serviceops_contract_after_version"):
        errors.append(f"{path.name}: contract migration requires serviceops_contract_after_version")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--changed-against")
    args = parser.parse_args()
    paths = args.paths or (changed_migrations(args.changed_against) if args.changed_against else [])
    errors = [error for path in paths for error in verify(path)]
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Migration safety policy passed for {len(paths)} changed migration(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
