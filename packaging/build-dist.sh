#!/usr/bin/env bash
# Assemble the ServiceOps "control plane" -- the CLI, install/operations
# scripts, and Compose/Helm definitions -- into a standalone distributable
# tree with no application source or Dockerfile, for packaging as an RPM (or
# any other host-level package). The actual application always ships as an
# immutable, pinned container image; this tree only ever pulls it.
set -Eeuo pipefail

VERSION="${1:?Usage: build-dist.sh VERSION [IMAGE_REPO] [IMAGE_DIGEST]}"
IMAGE_REPO="${2:-ghcr.io/awijesundara/serviceops}"
IMAGE_DIGEST="${3:-}"

if [[ -n "$IMAGE_DIGEST" ]]; then
  IMAGE_REF="$IMAGE_REPO@$IMAGE_DIGEST"
else
  echo "WARNING: no IMAGE_DIGEST given; pinning by mutable tag $IMAGE_REPO:$VERSION instead of an immutable digest." >&2
  echo "  Pass the pushed image's sha256 digest as the 3rd argument for a reproducible, tamper-evident install." >&2
  IMAGE_REF="$IMAGE_REPO:$VERSION"
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="$ROOT_DIR/dist/serviceops-$VERSION"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/tools/install"

cp "$ROOT_DIR/serviceops" "$STAGE_DIR/serviceops"
cp "$ROOT_DIR/compose.yaml" "$STAGE_DIR/compose.yaml"
cp "$ROOT_DIR/compose.external-db.yaml" "$STAGE_DIR/compose.external-db.yaml"
cp "$ROOT_DIR/.env.example" "$STAGE_DIR/.env.example"
cp "$ROOT_DIR/README.md" "$STAGE_DIR/README.md"
cp "$ROOT_DIR/tools/install/server.sh" "$STAGE_DIR/tools/install/server.sh"
cp "$ROOT_DIR/tools/install/kubernetes.sh" "$STAGE_DIR/tools/install/kubernetes.sh"
for f in rehearse-recovery.sh rehearse-pitr.sh rehearse-postgres-migrations.sh \
         rehearse-upgrade.sh recovery_verify.py cmdb_sync_agent.sh; do
  cp "$ROOT_DIR/tools/$f" "$STAGE_DIR/tools/$f"
done
cp -R "$ROOT_DIR/charts" "$STAGE_DIR/charts"
mkdir -p "$STAGE_DIR/docs"
cp "$ROOT_DIR"/docs/*.md "$STAGE_DIR/docs/" 2>/dev/null || true
echo "$VERSION" > "$STAGE_DIR/VERSION"

# No source/Dockerfile ships here -- strip the build: stanza from every
# compose file so `docker compose up` can only ever pull the pinned image.
python3 "$ROOT_DIR/packaging/strip_compose_build.py" \
  "$STAGE_DIR/compose.yaml" "$STAGE_DIR/compose.external-db.yaml"

# `up --build` has nothing to build from in a packaged install; pull instead.
sed -i.bak 's/"\${COMPOSE\[@\]}" up --build -d/"${COMPOSE[@]}" pull \&\& "${COMPOSE[@]}" up -d/' \
  "$STAGE_DIR/serviceops" "$STAGE_DIR/tools/install/server.sh"
rm -f "$STAGE_DIR/serviceops.bak" "$STAGE_DIR/tools/install/server.sh.bak"

# The installer's generated .env must point at the real published image, not
# a bare local tag that only exists after a local `docker build`. Prefer an
# immutable digest reference over a mutable tag when one was supplied.
sed -i.bak "s#SERVICEOPS_IMAGE=serviceops-app:[0-9][0-9.]*#SERVICEOPS_IMAGE=$IMAGE_REF#" \
  "$STAGE_DIR/tools/install/server.sh"
rm -f "$STAGE_DIR/tools/install/server.sh.bak"

# The web (browser-based) installer builds its own Flask app from source and
# needs a Dockerfile this tree deliberately doesn't ship -- it isn't
# available in a packaged install, so drop it from the CLI's usage text and
# make the dispatcher fail with a clear message instead of a raw "No such
# file or directory" if someone tries it anyway.
python3 - "$STAGE_DIR/serviceops" <<'PATCH'
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
text = text.replace("  ./serviceops install web\n", "")
text = text.replace(
    '    web) exec "$ROOT_DIR/tools/install/web.sh" "$@" ;;\n',
    '    web) echo "The browser installer is not included in packaged installs. Use: serviceops install server" >&2; exit 2 ;;\n',
)
text = text.replace(
    "Run ./serviceops install web",
    "Run: serviceops install server --yes",
)
open(path, "w", encoding="utf-8").write(text)
PATCH

chmod 755 "$STAGE_DIR/serviceops" "$STAGE_DIR/tools/install/"*.sh "$STAGE_DIR/tools/"*.sh
chmod 644 "$STAGE_DIR/tools/recovery_verify.py"

find "$STAGE_DIR" -name '.DS_Store' -o -name '._*' | xargs -r rm -f
# COPYFILE_DISABLE keeps macOS tar from embedding AppleDouble (._*) resource-fork
# sidecar files, which rpmbuild's "unpackaged file" check would otherwise reject.
COPYFILE_DISABLE=1 tar -C "$ROOT_DIR/dist" -czf "$ROOT_DIR/dist/serviceops-$VERSION.tar.gz" "serviceops-$VERSION"
echo "Built $ROOT_DIR/dist/serviceops-$VERSION.tar.gz"
