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
TARGET_DIGEST="${2:-}"
BACKUP_REFERENCE="${SERVICEOPS_BACKUP_REFERENCE:-}"
# "digest" (default): the chart pulls by repo@digest, which requires the
# target registry to serve manifests by digest reference. Set to "tag" for
# registries that only serve by repo:tag (e.g. some Nexus Repository proxy
# configurations reject digest-only pulls). TARGET_DIGEST is still required
# and still verified below in both modes -- this only changes how the
# cluster pulls the already-verified image, never whether it was verified.
IMAGE_PINNING="${SERVICEOPS_IMAGE_PINNING:-digest}"

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
[[ "$TARGET_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "Pass the verified target image digest as the second argument (sha256:<64 hex characters>)."
[[ -n "$BACKUP_REFERENCE" ]] || die "SERVICEOPS_BACKUP_REFERENCE is required. Take and restore-test a database backup, then set this to its snapshot or dump identifier."
[[ "$IMAGE_PINNING" == "digest" || "$IMAGE_PINNING" == "tag" ]] || die "SERVICEOPS_IMAGE_PINNING must be 'digest' or 'tag'."

echo "Current release image tag: $current_tag"
echo "Target image tag:          $TARGET_TAG"
echo "Target image digest:       $TARGET_DIGEST"
echo "Image pinning mode:        $IMAGE_PINNING"
echo "Verified backup reference: $BACKUP_REFERENCE"

helm lint "$CHART" >/dev/null && ok "Helm chart lint passed"
python3 "$ROOT_DIR/tools/verify_supply_chain.py" >/dev/null && ok "Supply-chain policy verification passed"

candidate_manifest="$(helm template "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$VALUES_FILE" \
  --set-string "image.tag=$TARGET_TAG" --set-string "image.digest=$TARGET_DIGEST" \
  --set-string "image.pinning=$IMAGE_PINNING" \
  --set-string "database.backupReference=$BACKUP_REFERENCE")"

if [[ "$IMAGE_PINNING" == "tag" ]]; then
  command -v docker >/dev/null || die "docker (with buildx) is required to verify a tag-pinned image before deploy."
  image_ref="$(grep -m1 -E '^\s*image: ' <<<"$candidate_manifest" | sed -E 's/^\s*image:\s*"?([^"]*)"?\s*$/\1/')"
  [[ -n "$image_ref" ]] || die "Could not determine the rendered image reference to verify."
  repository="${image_ref%:*}"
  resolved_digest="$(docker buildx imagetools inspect "$repository:$TARGET_TAG" 2>/dev/null | awk '/^Digest:/{print $2}')"
  [[ -n "$resolved_digest" ]] || die "Could not resolve $repository:$TARGET_TAG in the target registry to verify its digest."
  [[ "$resolved_digest" == "$TARGET_DIGEST" ]] || die "Refusing to deploy: $repository:$TARGET_TAG currently resolves to $resolved_digest, not the verified digest $TARGET_DIGEST. The tag may have moved since it was verified."
  ok "Confirmed $repository:$TARGET_TAG in the target registry still resolves to the verified digest"
fi
progressive_delivery=false
if grep -q '^kind: Rollout$' <<<"$candidate_manifest"; then
  progressive_delivery=true
  kubectl api-resources --api-group=argoproj.io -o name | grep -qx 'rollouts.argoproj.io' \
    || die "progressiveDelivery is enabled but the Argo Rollouts CRD is unavailable."
fi

previous_revision="$(helm history "$RELEASE" -n "$NAMESPACE" --max 1 -o json \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['revision'])")"
echo "Current revision: $previous_revision (helm rollback $RELEASE $previous_revision -n $NAMESPACE is the manual fallback)"

echo "Applying the update with --atomic (automatic rollback on failure)..."
helm upgrade "$RELEASE" "$CHART" -n "$NAMESPACE" -f "$VALUES_FILE" \
  --set-string "image.tag=$TARGET_TAG" \
  --set-string "image.digest=$TARGET_DIGEST" \
  --set-string "image.pinning=$IMAGE_PINNING" \
  --set-string "database.backupReference=$BACKUP_REFERENCE" \
  --atomic --wait --timeout 10m

if [[ "$progressive_delivery" == true ]]; then
  kubectl wait "rollout/$RELEASE" -n "$NAMESPACE" \
    --for=jsonpath='{.status.phase}'=Healthy --timeout=10m
else
  kubectl rollout status "deployment/$RELEASE" -n "$NAMESPACE" --timeout=5m
fi
kubectl rollout status "deployment/$RELEASE-worker" -n "$NAMESPACE" --timeout=5m
helm test "$RELEASE" -n "$NAMESPACE" --logs
ok "Rollout and packaged health test passed"

echo "Updated $RELEASE to image tag $TARGET_TAG."
echo "If a problem surfaces after this check, roll back manually with:"
echo "  helm rollback $RELEASE $previous_revision -n $NAMESPACE"
