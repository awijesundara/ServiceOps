from pathlib import Path

import pytest

from tools.wait_for_database import wait_for_database


ROOT = Path(__file__).resolve().parent.parent


def test_database_waiter_retries_without_leaking_exception_details(monkeypatch, capsys):
    attempts = iter([RuntimeError("postgresql://user:secret@db/app"), (True, set())])

    def fake_state(_database_url):
        result = next(attempts)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr("tools.wait_for_database.database_state", fake_state)
    monkeypatch.setattr("tools.wait_for_database.time.sleep", lambda _seconds: None)
    wait_for_database("postgresql://user:secret@db/app", 10, False)
    output = capsys.readouterr().out
    assert "RuntimeError" in output
    assert "secret" not in output


def test_database_waiter_blocks_until_expected_migration(monkeypatch, capsys):
    states = iter([(True, {"old"}), (True, {"head"})])
    monkeypatch.setattr("tools.wait_for_database.expected_heads", lambda: {"head"})
    monkeypatch.setattr("tools.wait_for_database.database_state", lambda _url: next(states))
    monkeypatch.setattr("tools.wait_for_database.time.sleep", lambda _seconds: None)
    wait_for_database("postgresql://db/app", 10, True)
    assert "waiting for migrations" in capsys.readouterr().out


def test_helm_workloads_gate_startup_on_database_and_schema():
    deployment = (ROOT / "charts/serviceops/templates/deployment.yaml").read_text()
    worker = (ROOT / "charts/serviceops/templates/worker.yaml").read_text()
    migration = (ROOT / "charts/serviceops/templates/migration-job.yaml").read_text()
    for workload in (deployment, worker):
        assert "database-and-schema-ready" in workload
        assert '"--migrations-current"' in workload
        assert "tools.wait_for_database" in workload
    assert "database-ready" in migration
    assert '"--migrations-current"' not in migration
    assert "Production requires persistent shared upload storage" in deployment


def test_safe_update_changes_the_governed_digest_and_is_atomic():
    script = (ROOT / "tools/safe_update_k8s.sh").read_text()
    assert 'TARGET_DIGEST="${2:-}"' in script
    assert '--set-string "image.digest=$TARGET_DIGEST"' in script
    assert "--atomic --wait" in script


def test_helm_health_test_is_not_captured_by_web_egress_policy_and_is_bounded():
    helpers = (ROOT / "charts/serviceops/templates/_helpers.tpl").read_text()
    policy = (ROOT / "charts/serviceops/templates/networkpolicy.yaml").read_text()
    health_test = (ROOT / "charts/serviceops/templates/tests/health-test.yaml").read_text()
    assert 'define "serviceops.webSelectorLabels"' in helpers
    assert 'include "serviceops.webSelectorLabels"' in policy
    assert "app.kubernetes.io/component: helm-test" in health_test
    assert ".Values.healthTest.image.repository" in health_test
    assert ".Values.healthTest.image.digest" in health_test
    assert "curlimages/curl:8.15.0" not in health_test
    assert '"--connect-timeout", "5", "--max-time", "15"' in health_test
    assert '"helm.sh/hook-delete-policy": before-hook-creation\n' in health_test
    assert "before-hook-creation,hook-succeeded" not in health_test
    assert 'name: {{ include "serviceops.fullname" . }}-health-test' in policy
    assert "app.kubernetes.io/component: helm-test" in policy
    assert 'include "serviceops.webSelectorLabels"' in policy


def test_production_ingress_requires_a_trusted_namespace_selector():
    deployment = (ROOT / "charts/serviceops/templates/deployment.yaml").read_text()
    assert "Production ingress requires networkPolicy.ingressNamespaceSelector" in deployment


def test_kubernetes_installer_creates_complete_split_secrets_once():
    installer = (ROOT / "tools/install/kubernetes.sh").read_text()
    assert 'command -v openssl' in installer
    assert "Partial secret state detected" in installer
    assert 'Existing runtime and bootstrap Secrets preserved' in installer
    for required in (
        "SECRET_KEY", "SETTINGS_ENCRYPTION_KEY", "AUDIT_INTEGRITY_KEY",
        "API_TOKEN_PEPPER", "DATABASE_URL", "LDAP_BIND_PASSWORD",
        "KEYCLOAK_CLIENT_SECRET",
    ):
        assert f"printf '{required}=%s" in installer
    assert "create secret generic serviceops-secrets" in installer
    assert "create secret generic serviceops-bootstrap" in installer
    assert "--from-env-file=\"$runtime_secret_file\"" in installer
    assert "--from-env-file=\"$bootstrap_secret_file\"" in installer
    assert '--from-env-file="$runtime_secret_file" --dry-run' not in installer
    assert '--from-env-file="$bootstrap_secret_file" --dry-run' not in installer
    assert "--set-string existingSecret=serviceops-secrets" in installer
    assert "--set-string existingBootstrapSecret=serviceops-bootstrap" in installer


def test_chart_requires_operator_managed_secrets():
    values = (ROOT / "charts/serviceops/values.yaml").read_text()
    helpers = (ROOT / "charts/serviceops/templates/_helpers.tpl").read_text()
    assert "secret:\n  create:" not in values
    assert not (ROOT / "charts/serviceops/templates/secret.yaml").exists()
    assert 'required "existingSecret is required"' in helpers
    assert 'required "existingBootstrapSecret is required"' in helpers
