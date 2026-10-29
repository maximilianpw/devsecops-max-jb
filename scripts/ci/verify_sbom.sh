#!/usr/bin/env bash
# Valide la SBOM d'une architecture avant toute écriture sur GHCR.
# Usage : verify_sbom.sh <amd64|arm64> ; l'artefact est déjà téléchargé dans
# dist/sbom/<arch>, l'archive d'image vérifiée dans dist/<arch>.
set -euo pipefail
arch=${1:?architecture}
: "${SBOM_ARTIFACT_ID:?contrat A : output sbom-artifact-id du job de scan absent}"
: "${EXPECTED_IMAGE_ID:?}" "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${GITHUB_SHA:?}" "${GITHUB_OUTPUT:?}"
[[ "$SBOM_ARTIFACT_ID" =~ ^[1-9][0-9]*$ ]] || { echo 'ID d artefact SBOM invalide' >&2; exit 1; }
ci=$(dirname "${BASH_SOURCE[0]}")
sbom_dir="dist/sbom/$arch"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Identité de l'artefact selon l'API (nom, run, commit), pas selon son contenu.
curl --retry 3 -fsS \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "${GITHUB_API_URL:-https://api.github.com}/repos/$GITHUB_REPOSITORY/actions/artifacts/$SBOM_ARTIFACT_ID" \
  -o "$work/artifact.json"
python3 "$ci/sbom_identity.py" artifact --metadata "$work/artifact.json" \
  --artifact-id "$SBOM_ARTIFACT_ID" --arch "$arch" --run-id "$GITHUB_RUN_ID" \
  --commit "$GITHUB_SHA" --run-attempt "$GITHUB_RUN_ATTEMPT"
for name in sbom.cdx.json sbom.spdx.json; do
  [ -f "$sbom_dir/$name" ] && [ ! -L "$sbom_dir/$name" ] \
    || { echo "$name absent ou non régulier dans l'artefact SBOM" >&2; exit 1; }
done
python3 "$ci/image_archive.py" describe "dist/$arch/image.tar" > "$work/image.json"
python3 - "$work/image.json" "$EXPECTED_IMAGE_ID" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['image_id'] == sys.argv[2], 'image ≠ output du build'
PY
args=(--sbom "$sbom_dir/sbom.cdx.json" --image-json "$work/image.json" --arch "$arch"
  --github-output "$GITHUB_OUTPUT")
[ "${SBOM_REQUIRE_CONFIG_DIGEST:-false}" = true ] && args+=(--require-config-digest)
python3 "$ci/sbom_identity.py" verify "${args[@]}"
