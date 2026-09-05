#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT_DIR/charts/serviceops"
NAMESPACE="${SERVICEOPS_NAMESPACE:-serviceops}"
RELEASE="${SERVICEOPS_RELEASE:-serviceops}"
VALUES_FILE="${SERVICEOPS_VALUES:-$ROOT_DIR/deploy/kubernetes/values-production.yaml}"
GITHUB_ORGANIZATION="${SERVICEOPS_GITHUB_ORGANIZATION:-}"
PREFLIGHT_ONLY=false
[[ "${1:-}" == "--preflight" ]] && PREFLIGHT_ONLY=true

die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
ok(){ printf 'PASS: %s\n' "$*"; }

command -v kubectl >/dev/null || die "kubectl is required."
command -v helm >/dev/null || die "Helm 3 is required."
command -v openssl >/dev/null || die "OpenSSL is required for cryptographic secret generation."
kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach the selected cluster."
server_version="$(kubectl version -o json | sed -n 's/.*"gitVersion": *"v\\([^"]*\\)".*/\\1/p' | tail -1)"
[[ -n "$server_version" ]] || die "Unable to determine Kubernetes server version."
ok "Kubernetes API is reachable (server $server_version)"
helm version --short | grep -Eq '^v3\\.' || die "Helm 3 is required."
ok "Helm 3 is available"

kubectl auth can-i create deployments.apps -n "$NAMESPACE" >/dev/null ||
  die "Current identity cannot create deployments in namespace $NAMESPACE."
ok "Required namespace deployment permission is available"

helm lint "$CHART" >/dev/null
ok "Helm chart lint passed"
python3 "$ROOT_DIR/tools/verify_supply_chain.py" >/dev/null
ok "Supply-chain policy verification passed"

if [[ "$PREFLIGHT_ONLY" == true ]]; then exit 0; fi
[[ -f "$VALUES_FILE" ]] || die "Create $VALUES_FILE from deploy/kubernetes/values-production.example.yaml."

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite >/dev/null
ok "Namespace exists with Restricted Pod Security admission labels"

[[ -n "$GITHUB_ORGANIZATION" ]] ||
  die "SERVICEOPS_GITHUB_ORGANIZATION is required for provenance admission."
kubectl auth can-i create clusterimagepolicies.policy.sigstore.dev >/dev/null ||
  die "Current identity cannot install the cluster image-attestation policy."
helm upgrade policy-controller --install --atomic \
  --create-namespace --namespace artifact-attestations \
  oci://ghcr.io/sigstore/helm-charts/policy-controller \
  --version 0.10.5 >/dev/null
helm upgrade trust-policies --install --atomic \
  --namespace artifact-attestations \
  oci://ghcr.io/github/artifact-attestations-helm-charts/trust-policies \
  --version v0.7.0 \
  --set policy.enabled=true \
  --set "policy.organization=$GITHUB_ORGANIZATION" \
  --set "policy.images[0]=ghcr.io/$GITHUB_ORGANIZATION/**" >/dev/null
kubectl label namespace "$NAMESPACE" \
  policy.sigstore.dev/include=true --overwrite >/dev/null
ok "GitHub provenance admission is enforced for the ServiceOps namespace"

runtime_secret_exists=false
bootstrap_secret_exists=false
kubectl get secret serviceops-secrets -n "$NAMESPACE" >/dev/null 2>&1 && runtime_secret_exists=true
kubectl get secret serviceops-bootstrap -n "$NAMESPACE" >/dev/null 2>&1 && bootstrap_secret_exists=true
if [[ "$runtime_secret_exists" != "$bootstrap_secret_exists" ]]; then
  die "Partial secret state detected; restore both serviceops-secrets and serviceops-bootstrap before deployment."
fi

if [[ "$runtime_secret_exists" == true ]]; then
  ok "Existing runtime and bootstrap Secrets preserved"
else
  runtime_secret_file="$(mktemp)"
  bootstrap_secret_file="$(mktemp)"
  chmod 600 "$runtime_secret_file" "$bootstrap_secret_file"
  trap 'rm -f "$runtime_secret_file" "$bootstrap_secret_file"' EXIT

  read -rsp "ServiceOps local administrator password: " admin_password; echo
  [[ ${#admin_password} -ge 14 ]] || die "Administrator password must be at least 14 characters."
  read -rsp "External PostgreSQL SQLAlchemy URL: " database_url; echo
  [[ "$database_url" == postgresql* ]] || die "A PostgreSQL URL is required."
  read -rsp "LDAP bind password (Enter if disabled): " ldap_password; echo
  read -rsp "Keycloak client secret (Enter if disabled): " keycloak_secret; echo

  {
    printf 'SECRET_KEY=%s\n' "$(openssl rand -hex 48)"
    printf 'SETTINGS_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32 | tr '+/' '-_')"
    printf 'AUDIT_INTEGRITY_KEY=%s\n' "$(openssl rand -hex 48)"
    printf 'API_TOKEN_PEPPER=%s\n' "$(openssl rand -hex 48)"
    printf 'DATABASE_URL=%s\n' "$database_url"
    printf 'LDAP_BIND_PASSWORD=%s\n' "$ldap_password"
    printf 'KEYCLOAK_CLIENT_SECRET=%s\n' "$keycloak_secret"
  } > "$runtime_secret_file"
  printf 'ADMIN_PASSWORD=%s\n' "$admin_password" > "$bootstrap_secret_file"

  kubectl create secret generic serviceops-secrets -n "$NAMESPACE" \
    --from-env-file="$runtime_secret_file" >/dev/null
  kubectl create secret generic serviceops-bootstrap -n "$NAMESPACE" \
    --from-env-file="$bootstrap_secret_file" >/dev/null
  ok "Split runtime/bootstrap Secrets created without command-line secret values"
fi

helm upgrade --install "$RELEASE" "$CHART" -n "$NAMESPACE" \
  -f "$VALUES_FILE" \
  --set-string existingSecret=serviceops-secrets \
  --set-string existingBootstrapSecret=serviceops-bootstrap \
  --atomic --wait --timeout 10m
kubectl rollout status "deployment/$RELEASE" -n "$NAMESPACE" --timeout=5m
helm test "$RELEASE" -n "$NAMESPACE" --logs
ok "ServiceOps rollout and packaged health test passed"
printf 'Inspect: kubectl get pods,pdb,networkpolicy,pvc,ingress -n %s\n' "$NAMESPACE"
