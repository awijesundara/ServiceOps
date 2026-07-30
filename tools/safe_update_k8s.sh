#!/usr/bin/env bash
# Safe, verified update for a Kubernetes/Helm ServiceOps deployment.
#
# Uses `helm upgrade --atomic`, which automatically rolls the release back to
# its previous revision if the upgrade (including the pre-upgrade migration
# Job and post-rollout readiness probes) fails. Runs the chart lint and
# supply-chain policy checks first, and the packaged Helm test afterward, so a
# broken candidate never reaches production traffic.
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT_DIR/charts/serviceops"
NAMESPACE="${SERVICEOPS_NAMESPACE:-serviceops}"
RELEASE="${SERVICEOPS_RELEASE:-serviceops}"
VALUES_FILE="${SERVICEOPS_VALUES:-$ROOT_DIR/deploy/kubernetes/values-production.yaml}"
TARGET_TAG="${1:-}"

die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
ok(){ printf '✓ %s\n' "$*"; }

command -v kubectl >/dev/null || die "kubectl is required."
command -v helm >/dev/null || die "Helm 3 is required."
kubectl cluster-info >/dev/null 2>&1 || die "kubectl cannot reach the selected cluster."
[[ -f "$VALUES_FILE" ]] || die "Missing $VALUES_FILE. Run ./serviceops install kubernetes first."
helm status "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1 || die "No existing release '$RELEASE' in namespace '$NAMESPACE'."

current_tag="$(helm get values "$RELEASE" -n "$NAMESPACE" -o json 2>/dev/null \
  | python3 -c "import json,sys; v=json.load(sys.stdin); print(v.get('image',{}).get('tag','unknown'))")"
default_tag="$(sed -n 's/^appVersion: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$CHART/Chart.yaml" | tail -1)"
[[ -n "$TARGET_TAG" ]] || TARGET_TAG="$default_tag"
[[ -n "$TARGET_TAG" ]] || die "Unable to determine a target image tag; pass one explicitly."

echo "Current release image tag: $current_tag"
echo "Target image tag:          $TARGET_TAG"

helm lint "$CHART" >/dev/null && ok "Helm chart lint passed"
python3 "$ROOT_DIR/tools/verify_supply_chain.py" >/dev/null && ok "Supply-chain policy verification passed"

previous_revision="$(helm history "$RELEASE" -n "$NAMESPACE" --max 1 -o json \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['revision'])")"
echo "Current revision: $previous_revision (helm rollback $RELEASE $previous_revision -n $NAMESPACE is the manual fallback)"

echo "Applying the update with --atomic (automatic rollback on failure)..."
helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$VALUES_FILE" \
  --set "image.tag=$TARGET_TAG" \
  --atomic --wait --timeout 10m

kubectl rollout status "deployment/$RELEASE" -n "$NAMESPACE" --timeout=5m
helm test "$RELEASE" -n "$NAMESPACE" --logs
ok "Rollout and packaged health test passed"

echo "Updated $RELEASE to image tag $TARGET_TAG."
echo "If a problem surfaces after this check, roll back manually with:"
echo "  helm rollback $RELEASE $previous_revision -n $NAMESPACE"
