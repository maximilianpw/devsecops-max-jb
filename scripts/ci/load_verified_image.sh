#!/usr/bin/env bash
# Valeurs attendues issues des outputs du job producteur ; jamais de l’artefact.
set -euo pipefail
dir="${1:?usage: load_verified_image.sh <dossier>}"
: "${IMAGE:?}" "${EXPECTED_IMAGE_ID:?}" "${EXPECTED_SHA256:?}" "${EXPECTED_PLATFORM:?}" "${EXPECTED_RUN_ATTEMPT:?}"
python3 scripts/ci/image_archive.py verify "$dir"
docker load --input "$dir/image.tar"
# Docker 29/containerd expose parfois le digest du manifeste dans .Id.
# Re-sauvegarder vérifie le config digest et les DiffIDs effectivement chargés.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
docker save --output "$work/loaded.tar" "$IMAGE"
python3 scripts/ci/image_archive.py describe "$work/loaded.tar" > "$work/loaded.json"
# Plateforme lue dans la configuration re-sauvegardée : `docker image inspect
# --platform` n'existe pas sur le Docker des runners GitHub.
read -r actual_id actual_platform < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["image_id"], d["platform"])' "$work/loaded.json")
[ "$actual_id" = "$EXPECTED_IMAGE_ID" ]
[ "$actual_platform" = "$EXPECTED_PLATFORM" ]
echo "Image vérifiée : $IMAGE ($actual_id, $actual_platform)"
