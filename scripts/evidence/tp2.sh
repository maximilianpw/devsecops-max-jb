#!/usr/bin/env bash
# Preuves TP2 séparées des mesures TP1 ; chaque étape échoue sur un écart.
set -euo pipefail
ARCH=${ARCH:-$(docker info --format '{{.Architecture}}')}
case "$ARCH" in aarch64) ARCH=arm64 ;; x86_64) ARCH=amd64 ;; amd64|arm64) ;; *) exit 1 ;; esac
export ARCH
export GITHUB_SHA=${GITHUB_SHA:-$(git rev-parse HEAD)}
export GITHUB_RUN_ID=${GITHUB_RUN_ID:-local-$(date +%s)}
export GITHUB_RUN_ATTEMPT=${GITHUB_RUN_ATTEMPT:-1}
out="evidence/tp2/$GITHUB_RUN_ID-$ARCH"
mkdir -p "$out"
export GITHUB_OUTPUT="$PWD/$out/outputs.txt"
export EXPECTED_PLATFORM="linux/$ARCH"
{
  date -u +%Y-%m-%dT%H:%M:%SZ
  git rev-parse HEAD
  git status --short
  docker version
  docker buildx version
  docker compose version
} > "$out/environment.txt"
steps="${*:-build run}"
for step in $steps; do
  case "$step" in
    build)
      : > "$GITHUB_OUTPUT"
      scripts/ci/build_variant.sh > "$out/build.txt" 2>&1
      cp dist/metadata.json "$out/metadata.json"
      cp reports/*.log "$out/" ;;
    run)
      IMAGE=$(sed -n 's/^image=//p' "$GITHUB_OUTPUT")
      export IMAGE
      scripts/ci/test_variant.sh > "$out/integration.txt" 2>&1 ;;
    scan)
      IMAGE=$(sed -n 's/^image=//p' "$GITHUB_OUTPUT")
      EXPECTED_IMAGE_ID=$(sed -n 's/^image_id=//p' "$GITHUB_OUTPUT")
      EXPECTED_SHA256=$(sed -n 's/^archive_sha256=//p' "$GITHUB_OUTPUT")
      EXPECTED_RUN_ATTEMPT=$(sed -n 's/^run_attempt=//p' "$GITHUB_OUTPUT")
      export IMAGE EXPECTED_IMAGE_ID EXPECTED_SHA256 EXPECTED_RUN_ATTEMPT
      scripts/ci/scan_variant.sh > "$out/scans.txt" 2>&1 ;;
    *) echo 'Étapes TP2 : build, run, scan (outils déjà installés)' >&2; exit 1 ;;
  esac
done
printf 'Preuves : %s\n' "$out"
