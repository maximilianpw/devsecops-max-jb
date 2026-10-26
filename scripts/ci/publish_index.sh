#!/usr/bin/env bash
# Appelé seulement après les gates, avec les archives vérifiées de ce run.
set -euo pipefail
: "${REPOSITORY:?}" "${VERSION:?}" "${MINOR:?}" "${MAJOR:?}"
: "${AMD64_ID:?}" "${ARM64_ID:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Une panne d’auth/réseau n’est jamais une preuve d’absence.
if crane digest "$REPOSITORY:$VERSION" > "$work/existing" 2> "$work/error"; then
  echo 'Version déjà publiée : réécriture interdite' >&2; exit 1
fi
if ! grep -Eq 'MANIFEST_UNKNOWN|NAME_UNKNOWN' "$work/error"; then
  echo "Impossible de prouver l’absence de la version (registre/auth/réseau)" >&2; exit 1
fi
for arch in amd64 arm64; do
  ref="$REPOSITORY:staging-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-$arch"
  crane push "dist/$arch/image.tar" "$ref"
  digest=$(crane digest "$ref")
  case "$arch" in amd64) expected=$AMD64_ID; amd64_digest=$digest ;; arm64) expected=$ARM64_ID; arm64_digest=$digest ;; esac
  crane manifest "$REPOSITORY@$digest" > "$work/manifest.json"
  python3 - "$work/manifest.json" "$expected" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['config']['digest'] == sys.argv[2]
PY
  crane pull "$REPOSITORY@$digest" "$work/remote.tar"
  python3 scripts/ci/image_archive.py describe "$work/remote.tar" > "$work/remote.json"
  python3 - "$work/remote.json" "$expected" "linux/$arch" <<'PY'
import json, sys
image = json.load(open(sys.argv[1]))
assert image['image_id'] == sys.argv[2] and image['platform'] == sys.argv[3]
PY
done
# Index candidat propre au run ; promouvoir seulement après validation exacte.
candidate="$REPOSITORY:staging-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-index"
docker buildx imagetools create -t "$candidate" "$REPOSITORY@$amd64_digest" "$REPOSITORY@$arm64_digest"
crane manifest "$candidate" > "$work/index.json"
python3 scripts/ci/check_index.py "$work/index.json" "$amd64_digest" "$arm64_digest"
index_digest=$(crane digest "$candidate")
for tag in "$VERSION" "$MINOR" "$MAJOR"; do
  crane tag "$REPOSITORY@$index_digest" "$tag"
  test "$(crane digest "$REPOSITORY:$tag")" = "$index_digest"
done
printf 'digest=%s\n' "$index_digest" >> "$GITHUB_OUTPUT"
echo "Index publié et tags vérifiés ; en cas d’échec, conserver les refs de staging pour diagnostic."
