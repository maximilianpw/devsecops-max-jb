#!/usr/bin/env bash
# Construction et contrôles secrets sur un builder dédié ; cache registre par
# architecture, importé anonymement à chaque build, exporté seulement sur
# contexte de confiance.
set -euo pipefail
: "${ARCH:?}" "${GITHUB_SHA:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
case "$ARCH" in amd64|arm64) ;; *) exit 1 ;; esac
export IMAGE=flask-api TAG="ci-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${ARCH}"
: "${GITHUB_REPOSITORY:=maximilianpw/devsecops-max-jb}"
cache_repository=$(printf '%s' "$GITHUB_REPOSITORY" | tr '[:upper:]' '[:lower:]')
# Import du cache registre déclaré dans docker-bake.hcl ; export seulement en fin
# de script (CACHE_EXPORT=true), après l'audit local.
export CACHE_REF="ghcr.io/${cache_repository}:buildcache-${ARCH}" CACHE_EXPORT=false
export CI_PLATFORM="linux/$ARCH"
export BUILD_SECRET_FILE
work=$(mktemp -d)
BUILD_SECRET_FILE="$work/build_token"
builder="tp2-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${ARCH}"
# Logs bruts dans l'espace privé ; seuls les logs audités sans jeton sont copiés
# vers reports/ (publié), y compris après un échec ou une interruption.
logs="$work/logs"
# Export registre uniquement sur entrée explicite ET contexte push main/tag.
registry_cache_write=false
if [[ "${CACHE_WRITE:-false}" == "true" && "${GITHUB_EVENT_NAME:-}" == "push" ]]; then
  ref="${GITHUB_REF:-}"
  case "$ref" in
    refs/heads/main|refs/tags/*) registry_cache_write=true ;;
  esac
fi
cleanup() {
  rc=$?
  trap - EXIT
  if [ -s "$BUILD_SECRET_FILE" ] && [ -n "$(ls -A "$logs" 2>/dev/null)" ]; then
    python3 scripts/ci/audit_secret.py --publish-to reports "$BUILD_SECRET_FILE" "$logs"/* || rc=1
  fi
  docker buildx rm "$builder" >/dev/null 2>&1 || true
  docker buildx rm "$builder-fresh" >/dev/null 2>&1 || true
  docker logout ghcr.io >/dev/null 2>&1 || true
  rm -rf "$work" dist/layer-cache
  exit "$rc"
}
trap cleanup EXIT
mkdir -p dist reports
chmod 0700 "$work"
mkdir "$logs"
{ printf 'TP2_'; openssl rand -hex 24 | tr -d '\n'; } > "$BUILD_SECRET_FILE"
chmod 0600 "$BUILD_SECRET_FILE"
docker buildx create --name "$builder" --driver docker-container --use
docker buildx inspect --bootstrap > "$logs/buildkit-version.txt"
docker buildx version >> "$logs/buildkit-version.txt"
# Git et contexte : le chemin source contractuel est exclu. Un COPY de secrets
# doit échouer dans un contexte identique, même avec un fichier factice présent.
git check-ignore -q secrets/build_token
cp -R .dockerignore "$work/.dockerignore"
printf 'FROM scratch\nCOPY secrets/build_token /token\n' > "$work/Dockerfile"
mkdir "$work/secrets"; cp "$BUILD_SECRET_FILE" "$work/secrets/build_token"
if docker buildx build --progress=plain "$work" > "$logs/context.log" 2>&1; then
  echo 'Le contexte expose secrets/build_token' >&2; exit 1
fi
grep -q 'not found\|excluded' "$logs/context.log"
# Ces builds sans cache doivent atteindre le contrôle du secret, jamais réussir
# grâce au résultat antérieur d’une couche.
if docker buildx build --platform "$CI_PLATFORM" --target builder --no-cache . > "$logs/absent.log" 2>&1; then
  echo 'Secret absent accepté' >&2; exit 1
fi
grep -q 'secret package_token: not found' "$logs/absent.log"
touch "$work/empty"
if docker buildx build --platform "$CI_PLATFORM" --target builder --no-cache \
  --secret "id=package_token,src=$work/empty" . > "$logs/empty.log" 2>&1; then
  echo 'Secret vide accepté' >&2; exit 1
fi
grep -q 'Build secret package_token must not be empty' "$logs/empty.log"
docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" -f docker-bake.hcl app-ci --progress=plain > "$logs/build.log" 2>&1
# Un cache registre chaud peut éviter entièrement pip et laisser son montage
# local vide. Réchauffer explicitement ce montage avant la preuve de réemploi.
docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" -f docker-bake.hcl app-ci \
  --set app-ci.target=builder --set "app-ci.tags=flask-api:warm-$TAG" \
  --no-cache --progress=plain > "$logs/pip-warm.log" 2>&1
# Cache pip : --no-cache ignorerait aussi le montage cache. On invalide donc
# seulement la couche pip, sur le même builder, via une copie du contexte dont
# requirements.txt diffère d'un commentaire. L'image publiée reste celle du bake.
mkdir "$work/pipctx"
cp Dockerfile .dockerignore requirements.txt app.py "$work/pipctx/"
printf '# invalidation TP2 de la couche pip\n' >> "$work/pipctx/requirements.txt"
docker buildx build --platform "$CI_PLATFORM" --target builder --progress=plain \
  --secret "id=package_token,src=$BUILD_SECRET_FILE" "$work/pipctx" > "$logs/pip-cache.log" 2>&1
grep -q 'Using cached' "$logs/pip-cache.log"
if grep -q ' Downloading ' "$logs/pip-cache.log"; then
  echo 'Cache pip partiellement réutilisé' >&2; exit 1
fi
docker save --output dist/image.tar "$IMAGE:$TAG"
# Export du builder pour couvrir également les couches du cache mode=max.
docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" -f docker-bake.hcl app-ci --set app-ci.target=builder \
  --set "app-ci.tags=flask-api:builder-$TAG" \
  --progress=plain > "$logs/builder.log" 2>&1
docker save --output dist/builder.tar "flask-api:builder-$TAG"
docker run --rm --platform "$CI_PLATFORM" --entrypoint python "flask-api:builder-$TAG" \
  -c "from pathlib import Path; assert not Path('/run/secrets/package_token').exists()"
python3 scripts/ci/audit_secret.py "$BUILD_SECRET_FILE" dist/image.tar dist/builder.tar "$logs"/*
# Contrôle positif du détecteur exact : une fuite volontaire doit bloquer.
if python3 scripts/ci/audit_secret.py "$BUILD_SECRET_FILE" "$work/secrets/build_token" > /dev/null 2>&1; then
  echo 'Détecteur de fuite inactif' >&2; exit 1
fi
# Un builder neuf recharge le cache externe local de couches (pas le cache pip).
docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" -f docker-bake.hcl app-ci --set 'app-ci.cache-to=type=local,dest=dist/layer-cache,mode=max' \
  --progress=plain > "$logs/cache-export.log" 2>&1
python3 scripts/ci/audit_secret.py "$BUILD_SECRET_FILE" dist/layer-cache/blobs/sha256/* "$logs/cache-export.log"
fresh="$builder-fresh"
docker buildx create --name "$fresh" --driver docker-container
if ! docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" --builder "$fresh" -f docker-bake.hcl app-ci \
  --set 'app-ci.cache-from=type=local,src=dist/layer-cache' \
  --progress=plain > "$logs/layer-cache.log" 2>&1; then
  exit 1
fi
docker buildx rm "$fresh"
grep -q 'CACHED' "$logs/layer-cache.log"
rm -rf dist/layer-cache
# Export registre uniquement sur contexte de confiance, après audit local.
if [[ "$registry_cache_write" == "true" ]]; then
  if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo 'Jeton GitHub absent pour l export du cache registre' >&2; exit 1
  fi
  printf '%s' "$GITHUB_TOKEN" | docker login ghcr.io --username "${GITHUB_ACTOR:-}" --password-stdin > "$logs/registry-login.log" 2>&1
  CACHE_EXPORT=true docker buildx bake --allow "fs.read=$BUILD_SECRET_FILE" -f docker-bake.hcl app-ci \
    --progress=plain > "$logs/cache-registry-export.log" 2>&1
  python3 scripts/ci/audit_secret.py "$BUILD_SECRET_FILE" "$logs/cache-registry-export.log"
  python3 scripts/ci/audit_registry_cache.py --secret-file "$BUILD_SECRET_FILE" --ref "$CACHE_REF"
fi
# Le jeton source est détruit à la sortie ; Trivy le reconnaît par sa forme TP2_.
python3 scripts/ci/image_archive.py describe dist/image.tar > "$work/image.json"
python3 - "$work/image.json" <<'PY'
import hashlib, json, os
from pathlib import Path
meta = json.loads(Path(__import__('sys').argv[1]).read_text())
with Path('dist/image.tar').open('rb') as stream:
    meta['archive_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
meta.update(commit=os.environ['GITHUB_SHA'], run_id=os.environ['GITHUB_RUN_ID'],
            run_attempt=os.environ['GITHUB_RUN_ATTEMPT'])
assert meta['platform'] == os.environ['CI_PLATFORM']
Path('dist/metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
    for key in ['image_id', 'archive_sha256', 'platform', 'run_attempt']:
        print(f'{key}={meta[key]}', file=out)
    print(f'image={os.environ["IMAGE"]}:{os.environ["TAG"]}', file=out)
PY
