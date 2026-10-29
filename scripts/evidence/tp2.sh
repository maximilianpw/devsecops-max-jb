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
    bench)
      (
        work=$(mktemp -d)
        chmod 0700 "$work"
        export BUILD_SECRET_FILE="$work/build_token" CI_PLATFORM="linux/$ARCH"
        builder="tp2-bench-$GITHUB_RUN_ID-$ARCH"
        cleanup() {
          rc=$?
          python3 scripts/ci/audit_secret.py --publish-to "$out" "$BUILD_SECRET_FILE" "$work"/*.log || rc=1
          docker buildx rm "$builder" >/dev/null 2>&1 || true
          rm -rf "$work"
          exit "$rc"
        }
        trap cleanup EXIT
        { printf 'TP2_'; openssl rand -hex 24 | tr -d '\n'; } > "$BUILD_SECRET_FILE"
        chmod 0600 "$BUILD_SECRET_FILE"
        docker buildx create --name "$builder" --driver docker-container --bootstrap > "$work/bench-builder.log" 2>&1
        docker buildx inspect "$builder" >> "$work/bench-builder.log"
        : > "$out/timings.txt"
        # Contexte copié dont requirements.txt diffère d'un commentaire : seule
        # la couche pip est invalidée, comme dans build_variant.sh.
        timed() {
          mkdir "$work/$1"
          cp Dockerfile .dockerignore requirements.txt app.py "$work/$1/"
          printf '# bench %s\n' "$1" >> "$work/$1/requirements.txt"
          TIMEFORMAT="$1 %R"
          { time docker buildx bake --builder "$builder" --allow "fs.read=$work" -f docker-bake.hcl app-ci \
              --set "app-ci.context=$work/$1" --set app-ci.output=type=cacheonly --progress=plain \
              > "$work/bench-$1.log" 2>&1; } 2>> "$out/timings.txt"
        }
        timed cold
        timed warm-minor
        docker buildx prune --builder "$builder" --filter type=exec.cachemount -f > "$work/bench-prune.log" 2>&1
        timed no-pip-cache
        grep -q 'Using cached' "$work/bench-warm-minor.log"
        ! grep -q ' Downloading ' "$work/bench-warm-minor.log" || exit 1
        grep -q ' Downloading ' "$work/bench-no-pip-cache.log"
        ! grep -q 'Using cached' "$work/bench-no-pip-cache.log" || exit 1
      ) ;;
    *) echo 'Étapes TP2 : build, run, scan, bench (outils déjà installés)' >&2; exit 1 ;;
  esac
done
printf 'Preuves : %s\n' "$out"
