"""Release-gate coverage for the RPM/systemd distribution."""

import json
import os
import subprocess
import tarfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_rpm_distribution_contains_every_host_control_plane_dependency():
    version = (ROOT / "VERSION").read_text().strip()
    subprocess.run(
        ["bash", "packaging/build-dist.sh", version, "ghcr.io/example/serviceops", "sha256:" + "a" * 64],
        cwd=ROOT, check=True, capture_output=True, text=True,
    )
    archive = ROOT / "dist" / f"serviceops-{version}.tar.gz"
    with tarfile.open(archive) as bundle:
        names = {member.name for member in bundle.getmembers()}
        prefix = f"serviceops-{version}/"
        required = {
            "serviceops", "serviceops.spec", "compose.yaml", "compose.external-db.yaml",
            "compose.blue-green.yaml", "packaging/systemd/serviceops.service",
            "packaging/systemd/serviceops-health.service",
            "packaging/systemd/serviceops-health.timer",
            "packaging/systemd/serviceops-backup.service",
            "packaging/systemd/serviceops-backup.timer",
            "packaging/logrotate/serviceops",
            "tools/install/server.sh", "tools/install/package.sh", "tools/safe_update.sh",
            "tools/blue_green_bootstrap.sh", "tools/blue_green_deploy.sh",
            "tools/blue_green_rollback.sh", "tools/rehearse-postgres-migrations.sh",
            "tools/postgres_migration_rehearsal.py", "tools/recovery_verify.py",
            "tools/stability_probe.py", "tools/stress_test.py", "tools/backup_retention.py",
        }
        assert {prefix + path for path in required}.issubset(names)
        installer = bundle.extractfile(prefix + "tools/install/server.sh").read().decode()
        assert "docker compose" in installer
        assert "up --build" not in installer
        assert "ghcr.io/example/serviceops@sha256:" + "a" * 64 in installer


def test_rpm_declares_runtime_dependencies_and_systemd_lifecycle():
    spec = (ROOT / "packaging/rpm/serviceops.spec").read_text()
    for dependency in (
        "docker-ce", "docker-compose-plugin", "curl", "openssl",
        "bash", "python3", "python3-requests", "tar", "gzip", "logrotate",
    ):
        assert f"Requires:       {dependency}" in spec
    assert "%systemd_post serviceops.service" in spec
    assert "%systemd_preun serviceops.service" in spec
    assert "%systemd_postun_with_restart serviceops.service" in spec
    assert "%config(noreplace)" in spec


def test_systemd_unit_runs_as_dedicated_unprivileged_account():
    unit = (ROOT / "packaging/systemd/serviceops.service").read_text()
    assert "User=serviceops" in unit
    assert "Group=serviceops" in unit
    assert "SupplementaryGroups=docker" in unit
    assert "ConditionPathExists=/etc/serviceops/serviceops.env" in unit
    assert "ExecStartPre=/usr/bin/serviceops config-check" in unit
    assert "ExecStart=/usr/bin/serviceops start" in unit
    assert "ExecStop=/usr/bin/serviceops stop" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "UMask=0077" in unit


def test_package_manages_health_and_backup_timers_without_enabling_them_in_scriptlets():
    spec = (ROOT / "packaging/rpm/serviceops.spec").read_text()
    assert "serviceops-health.timer" in spec
    assert "serviceops-backup.timer" in spec
    post_script = spec.split("%post\n", 1)[1].split("%preun\n", 1)[0]
    assert "systemctl enable" not in post_script
    setup = (ROOT / "tools/install/package.sh").read_text()
    assert "systemctl enable --now docker.service" in setup
    assert "systemctl enable --now serviceops.service" in setup
    assert "serviceops-health.timer serviceops-backup.timer" in setup

    health = (ROOT / "packaging/systemd/serviceops-health.service").read_text()
    backup = (ROOT / "packaging/systemd/serviceops-backup.service").read_text()
    for unit in (health, backup):
        assert "User=serviceops" in unit
        assert "SupplementaryGroups=docker" in unit
        assert "UMask=0077" in unit
    assert "watchdog-heal" in health
    assert "scheduled-backup" in backup


def test_systemd_preflight_does_not_render_secrets_to_the_journal():
    cli = (ROOT / "serviceops").read_text()
    assert 'config-check) "${COMPOSE[@]}" config --quiet ;;' in cli
    assert '"$command" == "config-check"' in cli


def test_root_installer_returns_packaged_secrets_to_service_account():
    installer = (ROOT / "tools/install/server.sh").read_text()
    assert '"$ROOT_DIR" == "/opt/serviceops"' in installer
    assert 'chown serviceops:serviceops "$ENV_FILE" "$STATE_FILE"' in installer


def test_backup_retention_preserves_minimum_and_ignores_incomplete_sets(tmp_path):
    now = time.time()
    for index in range(4):
        stamp = f"scheduled-{index}"
        database = tmp_path / f"serviceops-{stamp}.dump"
        uploads = tmp_path / f"serviceops-uploads-{stamp}.tar.gz"
        manifest = tmp_path / f"serviceops-{stamp}.manifest.json"
        database.write_bytes(b"database")
        uploads.write_bytes(b"uploads")
        manifest.write_text(json.dumps({
            "database": {"name": database.name},
            "uploads": {"name": uploads.name},
        }))
        old = now - (40 + index) * 86400
        os.utime(manifest, (old, old))

    incomplete = tmp_path / "serviceops-incomplete.manifest.json"
    incomplete.write_text("not-json")
    subprocess.run([
        "python3", "tools/backup_retention.py", str(tmp_path),
        "--days", "30", "--minimum-sets", "2",
    ], cwd=ROOT, check=True, capture_output=True, text=True)

    assert len(list(tmp_path.glob("*.dump"))) == 2
    assert len(list(tmp_path.glob("*.tar.gz"))) == 2
    assert incomplete.exists()
