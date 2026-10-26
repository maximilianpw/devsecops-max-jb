#!/usr/bin/env bash
# Valeurs attendues issues des outputs du job producteur ; jamais de l’artefact.
set -euo pipefail
dir="${1:?usage: load_verified_image.sh <dossier>}"
: "${IMAGE:?}" "${EXPECTED_IMAGE_ID:?}" "${EXPECTED_SHA256:?}" "${EXPECTED_PLATFORM:?}"
python3 scripts/ci/image_archive.py verify "$dir"
docker load --input "$dir/image.tar"
# Docker 29/containerd expose parfois le digest du manifeste dans .Id.
# Re-sauvegarder vérifie le config digest et les DiffIDs effectivement chargés.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
docker save --output "$work/loaded.tar" "$IMAGE"
python3 scripts/ci/image_archive.py describe "$work/loaded.tar" > "$work/loaded.json"
actual_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_id"])' "$work/loaded.json")
actual_platform="$(docker image inspect --platform "$EXPECTED_PLATFORM" --format '{{.Os}}/{{.Architecture}}' "$IMAGE")"
[ "$actual_id" = "$EXPECTED_IMAGE_ID" ]
[ "$actual_platform" = "$EXPECTED_PLATFORM" ]
echo "Image vérifiée : $IMAGE ($actual_id, $actual_platform)"
