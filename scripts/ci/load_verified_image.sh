#!/usr/bin/env bash
# Charge l'archive produite par le job build après avoir vérifié qu'il s'agit
# bien de l'image auditée : checksum de l'archive puis identifiant de l'image.
#
# Usage : load_verified_image.sh <répertoire de l'artefact>
# Variables requises : IMAGE, EXPECTED_IMAGE_ID, EXPECTED_SHA256.
set -euo pipefail

dir="${1:?usage: load_verified_image.sh <dossier>}"
: "${IMAGE:?}" "${EXPECTED_IMAGE_ID:?}" "${EXPECTED_SHA256:?}"

actual_sha256="$(sha256sum "$dir/image.tar" | cut -d' ' -f1)"
if [ "$actual_sha256" != "$EXPECTED_SHA256" ]; then
  echo "::error::Checksum de l'archive inattendu : $actual_sha256 (attendu $EXPECTED_SHA256)"
  exit 1
fi
(cd "$dir" && sha256sum --check --strict image.tar.sha256)

docker load --input "$dir/image.tar"

actual_id="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
if [ "$actual_id" != "$EXPECTED_IMAGE_ID" ]; then
  echo "::error::Image ID inattendu pour $IMAGE : $actual_id (attendu $EXPECTED_IMAGE_ID)"
  exit 1
fi
echo "Image vérifiée : $IMAGE ($actual_id)"
