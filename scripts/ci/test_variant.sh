#!/usr/bin/env bash
# Exerce réellement API et PostgreSQL sur la plateforme annoncée.
set -euo pipefail
: "${IMAGE:?}" "${EXPECTED_PLATFORM:?}"
work=$(mktemp -d)
chmod 0755 "$work"
export COMPOSE_PROJECT_NAME="tp2-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${EXPECTED_PLATFORM##*/}"
export API_IMAGE="$IMAGE" API_BASE_URL="http://127.0.0.1:${API_PORT:-5000}"
compose() { docker compose --env-file /dev/null -f docker-compose.yml -f "$work/override.yaml" "$@"; }
cleanup() {
  rc=$?
  trap - EXIT
  # Diagnostic best-effort : son échec ne doit empêcher ni down ni le nettoyage.
  if [ "$rc" -ne 0 ]; then compose logs --no-color || echo 'compose logs indisponible' >&2; fi
  if ! compose down --volumes --remove-orphans; then
    if [ "$rc" -eq 0 ]; then rc=1; fi
  fi
  if ! rm -rf "$work"; then
    if [ "$rc" -eq 0 ]; then rc=1; fi
  fi
  exit "$rc"
}
trap cleanup EXIT
openssl rand -hex 24 > "$work/db_password"
chmod 0644 "$work/db_password"
cat > "$work/override.yaml" <<EOF
services:
  api-python:
    platform: $EXPECTED_PLATFORM
    ports: !override
      - "127.0.0.1:${API_PORT:-5000}:5000"
  db:
    platform: $EXPECTED_PLATFORM
secrets:
  db_password:
    file: $work/db_password
EOF
compose up -d --no-build --wait --wait-timeout 180
for service in api-python db; do
  container=$(compose ps -q "$service")
  test -n "$container"
  test "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy
  # Architecture mesurée dans le conteneur : avec le stockage containerd,
  # inspecter l'image d'un index renvoie la plateforme de l'hôte.
  if [ "$service" = api-python ]; then
    machine=$(docker exec "$container" python -c 'import os; print(os.uname().machine)')
    test "$(docker inspect --format '{{.Image}}' "$container")" = "$(docker image inspect --format '{{.Id}}' "$IMAGE")"
  else
    machine=$(docker exec "$container" uname -m)
  fi
  case "$machine" in x86_64) machine=amd64 ;; aarch64) machine=arm64 ;; esac
  test "linux/$machine" = "$EXPECTED_PLATFORM"
done
"${PYTHON:-python3}" -m pytest -m integration tests/integration
