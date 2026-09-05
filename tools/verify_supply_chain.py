"""Fail closed when release/deployment supply-chain controls drift."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SHA_PIN = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def verify_supply_chain() -> dict[str, object]:
    errors = []
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [
        line.strip() for line in dockerfile.splitlines()
        if line.lstrip().startswith("FROM ")
    ]
    if not from_lines or any("@sha256:" not in line for line in from_lines):
        errors.append("Every Dockerfile base image must be digest-pinned.")

    workflow = (
        ROOT / ".github/workflows/supply-chain.yml"
    ).read_text(encoding="utf-8")
    action_lines = [
        line for line in workflow.splitlines() if line.lstrip().startswith("uses:")
    ]
    if not action_lines or any(not SHA_PIN.match(line) for line in action_lines):
        errors.append("Every GitHub Action must be pinned to a full commit SHA.")
    for required in (
        "trivy-action@", "cosign-installer@", "actions/attest@",
        "cosign sign --yes", "gh attestation verify",
        "docker buildx imagetools inspect",
    ):
        if required not in workflow:
            errors.append(f"Supply-chain workflow is missing {required!r}.")

    deployment_workflow = (
        ROOT / ".github/workflows/deploy-kubernetes.yml"
    ).read_text(encoding="utf-8")
    deployment_action_lines = [
        line for line in deployment_workflow.splitlines()
        if line.lstrip().startswith("uses:")
    ]
    if not deployment_action_lines or any(
        not SHA_PIN.match(line) for line in deployment_action_lines
    ):
        errors.append("Every Kubernetes deployment action must be pinned to a full commit SHA.")
    for required in (
        "gh attestation verify", 'image.digest=$IMAGE_DIGEST', "--atomic --wait",
        "KUBE_CONFIG_B64", "KUBERNETES_VALUES_B64", "environment: production",
    ):
        if required not in deployment_workflow:
            errors.append(f"Kubernetes deployment workflow is missing {required!r}.")

    values = (ROOT / "charts/serviceops/values.yaml").read_text(encoding="utf-8")
    match = re.search(r"^\s*digest:\s*[\"']?([^\"' ]+)", values, re.MULTILINE)
    if not match or not DIGEST.fullmatch(match.group(1)):
        errors.append("Helm default image digest must be a SHA-256 digest.")
    for template in ("deployment.yaml", "worker.yaml", "migration-job.yaml"):
        content = (
            ROOT / "charts/serviceops/templates" / template
        ).read_text(encoding="utf-8")
        if 'include "serviceops.imageRef"' not in content:
            errors.append(f"{template} does not use the governed digest image reference.")

    installer = (
        ROOT / "tools/install/kubernetes.sh"
    ).read_text(encoding="utf-8")
    if "policy.sigstore.dev/include" not in installer:
        errors.append("Kubernetes installer does not enable attestation admission.")
    if errors:
        raise RuntimeError("Supply-chain verification failed: " + " ".join(errors))
    return {
        "valid": True,
        "action_pins": len(action_lines) + len(deployment_action_lines),
        "dockerfile_bases": len(from_lines),
        "kubernetes_digest_enforced": True,
        "attestation_admission_enabled": True,
    }


if __name__ == "__main__":
    print(json.dumps(verify_supply_chain(), sort_keys=True))
