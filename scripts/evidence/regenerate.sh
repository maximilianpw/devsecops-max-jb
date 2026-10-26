#!/usr/bin/env bash
# Régénère les preuves de evidence/after/ liées à l'image, sur une seule image
# construite comme en CI (linux/amd64, sans attestations).
#
# Usage (depuis la racine du dépôt, Docker démarré) :
#   scripts/evidence/regenerate.sh [all|image|dive|trivy|run|compat|dockerignore|cache|functional|hardening]...
#
# Prérequis : Docker avec Compose v2 et BuildKit, Dive 0.13.1, Trivy 0.75.0,
# Python 3.15 avec requirements-dev.txt (variable PYTHON, défaut python3).
# Les fichiers flake8.txt et hadolint.txt ne dépendent pas de l'image et ne
# sont pas régénérés ici. Aucun mot de passe n'est écrit dans les preuves.
set -euo pipefail

IMAGE=flask-api:local
PLATFORM=linux/amd64
OUT=evidence/after
PYTHON=${PYTHON:-python3}
TRIVY=${TRIVY:-trivy}
DIVE=${DIVE:-dive}
ROOT=$(pwd)
BUILDER=$(sed -n 's/^FROM \([^ ]*\) AS builder$/\1/p' Dockerfile)
DB_IMAGE=$(docker compose config --no-interpolate --format json \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["services"]["db"]["image"])')

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }
image_id() { docker image inspect --format '{{.Id}}' "$IMAGE"; }
# Python de l'image finale (pas de shell dans l'image).
in_image() { docker run --rm --platform "$PLATFORM" --entrypoint /app/venv/bin/python "$IMAGE" -c "$1"; }
trivy_header() {
  echo "# Version: $("$TRIVY" --version | sed -n 's/^Version: //p')"
  "$TRIVY" --version | sed -n '/Vulnerability DB/,$p' | sed 's/^/# /'
}

build() {
  docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
    --load -t "$IMAGE" . >/dev/null 2>&1
  echo "image construite : $IMAGE $(image_id)"
}

gen_image() {
  local id json size
  id=$(image_id)
  json=$(mktemp)
  "$DIVE" "$IMAGE" --json "$json" >/dev/null 2>&1
  size=$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"]["sizeBytes"])' "$json")
  rm -f "$json"
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $id"
    echo "# tailles : octets non compressés (somme des couches, dive --json), comme dive.txt ; docker image inspect .Size (contenu compressé, magasin containerd de Docker Desktop) = $(docker image inspect --format '{{.Size}}' "$IMAGE") octets"
    echo "## configuration"
    docker image inspect --format 'id={{.Id}} os/arch={{.Os}}/{{.Architecture}}
Config.User={{.Config.User}}
Entrypoint={{json .Config.Entrypoint}} Cmd={{json .Config.Cmd}}' "$IMAGE"
    echo "size_bytes=$size"
    "$PYTHON" -c 'import sys; print(f"size_MB={int(sys.argv[1]) / 1e6:.1f} (10^6 octets)")' "$size"
    echo "## utilisateur effectif"
    in_image 'import os, pwd; print("uid", os.getuid(), "gid", os.getgid(), "nom", pwd.getpwuid(os.getuid()).pw_name)'
    echo "## shell : docker run --entrypoint /bin/sh $IMAGE -c 'echo shell'"
    set +e
    docker run --rm --platform "$PLATFORM" --entrypoint /bin/sh "$IMAGE" -c 'echo shell' 2>&1
    echo "exit: $?"
    set -e
    echo "## binaires et modules (recherche dans PATH et /bin, /sbin, /usr/bin, /usr/sbin)"
    in_image '
import importlib.util, os, shutil
path = os.pathsep.join([os.environ["PATH"], "/bin", "/sbin", "/usr/bin", "/usr/sbin"])
for name in ["sh", "bash", "ash", "dash", "busybox", "apk", "apt", "apt-get", "dpkg",
             "pip", "pip3", "gcc", "cc", "make", "curl", "wget"]:
    found = shutil.which(name, path=path)
    print(name + ":", "présent " + found if found else "absent")
for module in ["pip", "ensurepip", "setuptools", "pytest"]:
    print("module " + module + ":", "présent" if importlib.util.find_spec(module) else "absent")
'
    echo "## contenu et permissions de /app"
    in_image '
import os, stat
for p in ["/app", "/app/app.py", "/app/venv", "/app/venv/bin/python"]:
    s = os.lstat(p)
    link = f" -> {os.readlink(p)}" if stat.S_ISLNK(s.st_mode) else ""
    print(p, oct(s.st_mode), f"uid={s.st_uid} gid={s.st_gid}{link}")
print("/app :", sorted(os.listdir("/app")))
print("/app/venv/bin :", sorted(os.listdir("/app/venv/bin")))
for p in ["/app", "/app/app.py", "/app/venv", "/app/venv/lib/python3.15/site-packages"]:
    print(f"écriture {p} :", os.access(p, os.W_OK))
writable = [os.path.join(d, n) for d, ds, fs in os.walk("/app") for n in ds + fs
            if os.access(os.path.join(d, n), os.W_OK)]
print("entrées de /app modifiables par l utilisateur :", len(writable), writable[:5])
'
    echo "## paquets Python installés"
    in_image 'import importlib.metadata as m; [print(d.metadata["Name"] + "==" + d.version) for d in sorted(m.distributions(), key=lambda d: d.metadata["Name"])]'
    echo "## couches"
    docker history --format '{{.Size}}\t{{.CreatedBy}}' "$IMAGE"
  } > "$OUT/image.txt"
}

gen_dive() {
  local status
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: dive --ci --ci-config .dive-ci $IMAGE (commande de la CI)"
    set +e
    "$DIVE" --ci --ci-config .dive-ci "$IMAGE" > /tmp/dive.out 2>&1
    status=$?
    set -e
    echo "# exit: $status"
    strip_ansi < /tmp/dive.out
  } > "$OUT/dive.txt"
  rm -f /tmp/dive.out
}

gen_trivy() {
  local status
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: trivy image --platform $PLATFORM $IMAGE (toutes sévérités)"
    trivy_header
    set +e
    "$TRIVY" image -q --platform "$PLATFORM" "$IMAGE" > /tmp/trivy.out 2>&1
    status=$?
    set -e
    echo "# exit: $status"
    cat /tmp/trivy.out
  } > "$OUT/trivy.txt"
  {
    echo "# date: $(now)"
    echo "# cmd: trivy image --image-src remote --platform $PLATFORM $DB_IMAGE (toutes sévérités)"
    trivy_header
    set +e
    "$TRIVY" image -q --image-src remote --platform "$PLATFORM" "$DB_IMAGE" > /tmp/trivy.out 2>&1
    status=$?
    set -e
    echo "# exit: $status"
    cat /tmp/trivy.out
    echo
    echo "## gate HIGH/CRITICAL corrigibles"
    echo "# date: $(now)"
    echo "# cmd: trivy image --image-src remote --platform $PLATFORM --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table $DB_IMAGE"
    set +e
    "$TRIVY" image -q --image-src remote --platform "$PLATFORM" --scanners vuln \
      --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
      --format table "$DB_IMAGE" > /tmp/trivy.out 2>&1
    status=$?
    set -e
    echo "# exit: $status"
    cat /tmp/trivy.out
  } > "$OUT/trivy-db.txt"
  {
    echo "# date: $(now)"
    echo "# cmd: trivy fs --scanners vuln requirements.txt"
    trivy_header
    set +e
    "$TRIVY" fs -q --scanners vuln requirements.txt > /tmp/trivy.out 2>&1
    status=$?
    set -e
    echo "# exit: $status"
    cat /tmp/trivy.out
  } > "$OUT/trivy-deps.txt"
  rm -f /tmp/trivy.out
}

http_get() {
  "$PYTHON" - "$1" <<'PY'
import sys, urllib.error, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
        status, body = r.status, r.read().decode()
except urllib.error.HTTPError as e:
    status, body = e.code, e.read().decode()
print(body.strip(), status)
PY
}

wait_health() {
  for _ in $(seq 1 30); do
    "$PYTHON" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)' \
      "$1" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

gen_run() {
  local name=evidence-run
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --platform "$PLATFORM" --read-only --cap-drop ALL \
    --security-opt no-new-privileges -p 127.0.0.1:5051:5000 "$IMAGE" >/dev/null
  wait_health http://127.0.0.1:5051/health
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: docker run --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:5051:5000 $IMAGE (sans base de données)"
    for path in health hello dbtest; do
      echo "GET /$path -> $(http_get "http://127.0.0.1:5051/$path")"
    done
    sleep 1
    echo "## journaux"
    docker logs "$name" 2>&1 | grep -v '"GET ' | head -6
  } > "$OUT/image-run.txt"
  docker rm -f "$name" >/dev/null
}

gen_compat() {
  local info='import platform, sys, sysconfig; print("python", platform.python_version(), "abi", sysconfig.get_config_var("SOABI").split("-")[0] + "-" + sysconfig.get_config_var("SOABI").split("-")[1], "arch", platform.machine(), "libc", platform.libc_ver())'
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# compatibilité builder / runtime ($PLATFORM)"
    echo "builder: $(docker run --rm --platform "$PLATFORM" --entrypoint python "$BUILDER" -c "$info")"
    echo "runtime: $(in_image "$info")"
    in_image '
import os, psycopg2, psycopg2.extensions as e, sysconfig
print("psycopg2", psycopg2.__version__, "libpq", e.libpq_version())
libs = os.path.join(os.path.dirname(os.path.dirname(psycopg2.__file__)), "psycopg2_binary.libs")
print("bibliothèques embarquées par psycopg2-binary:", sorted(os.listdir(libs)))
d = sysconfig.get_config_var("WHEEL_PKG_DIR")
print("WHEEL_PKG_DIR", d, sorted(os.listdir(d)) if d and os.path.isdir(d) else "absent")
'
    set +e
    docker run --rm --platform "$PLATFORM" --entrypoint /app/venv/bin/python "$IMAGE" \
      -m ensurepip >/dev/null 2>&1
    echo "# python -m ensurepip dans le runtime : échec (aucun site-packages accessible en écriture), exit: $?"
    set -e
  } > "$OUT/runtime-compat.txt"
}

gen_dockerignore() {
  local work
  work=$(mktemp -d)
  cp -R "$ROOT/." "$work/repo"
  (
    cd "$work/repo"
    mkdir -p .venv __pycache__ .pytest_cache htmlcov logs
    for f in .coverage .env .env.local backup.tar.gz debug.log dump.zip notes.md \
             secrets.json server.key logs/app.log; do
      echo parasite > "$f"
    done
    printf 'FROM %s\nCOPY . /ctx\nRUN find /ctx -mindepth 1 | sort\n' "$BUILDER" > "$work/Dockerfile.ctx"
    {
      echo "# date: $(now)"
      echo "# contrôle du .dockerignore : copie du dépôt (avec .git) dans laquelle des fichiers parasites ont été ajoutés, puis build d'un Dockerfile de test qui liste le contexte reçu"
      echo "## contenu du dossier"
      ls -A | sort -f | tr '\n' ' '; echo
      echo "## Dockerfile de test"
      sed 's/^/    /' "$work/Dockerfile.ctx"
      echo "## fichiers reçus par le build"
      docker buildx build --platform "$PLATFORM" --no-cache --progress=plain \
        -f "$work/Dockerfile.ctx" . 2>&1 | sed -n 's/^#[0-9]* [0-9.]* \(\/ctx\/.*\)$/\1/p'
    } > "$ROOT/$OUT/dockerignore.txt"
  )
  rm -rf "$work"
}

gen_cache() {
  local work ref
  work=$(mktemp -d)
  cp -R "$ROOT/." "$work/repo"
  ref=$(image_id)
  (
    cd "$work/repo"
    docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
      --load -t flask-api:cachetest . >/dev/null 2>&1
    copy_id=$(docker image inspect --format '{{.Id}}' flask-api:cachetest)
    echo "# modification de test" >> app.py
    {
      echo "# date: $(now) (fin du test ; copie du dépôt dans /tmp, app.py du dépôt non modifié)"
      echo "# image de référence : $IMAGE $ref (build de la copie avant modification identique : $([ "$copy_id" = "$ref" ] && echo oui || echo "non, $copy_id"))"
      echo "# contrôle du cache : rebuild après modification de app.py seul"
      echo "# cmd: docker buildx build --platform $PLATFORM --provenance=false --sbom=false --load --progress=plain -t flask-api:cachetest ."
      docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
        --load --progress=plain -t flask-api:cachetest . 2>&1 \
        | grep -E '^#[0-9]+ (\[|CACHED)'
    } > "$ROOT/$OUT/build-cache.txt"
  )
  docker image rm flask-api:cachetest >/dev/null
  rm -rf "$work"
}

# Stack Compose comme en CI : image auditée, identifiants de test, secret fichier.
compose_env() {
  export COMPOSE_PROJECT_NAME=$1 API_IMAGE=$IMAGE DB_USER=ci_user DB_NAME=ci_db
}
new_secret() {
  install -d -m 0755 secrets
  printf '%s' "$(openssl rand -hex 24)" > secrets/db_password
  chmod 0644 secrets/db_password
}
compose() { docker compose --env-file /dev/null "$@"; }
# Sortie de docker compose sans la ligne d'avertissement de plateforme, propre à l'hôte arm64.
# Le code retour est celui de docker compose.
compose_log() {
  local rc=0 out
  out=$(mktemp)
  compose "$@" > "$out" 2>&1 || rc=$?
  grep -v 'does not match the detected host platform' "$out" || true
  rm -f "$out"
  return "$rc"
}

gen_functional() {
  local id status
  id=$(image_id)
  compose_env functional-check
  new_secret
  {
    echo "# date: $(now)"
    echo "# contrôle fonctionnel : image $IMAGE $id ($PLATFORM, Docker Desktop macOS arm64) servie par gunicorn dans la stack docker-compose.yml réelle"
    echo "# variables : COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME API_IMAGE=$API_IMAGE DB_USER=$DB_USER DB_NAME=$DB_NAME, --env-file /dev/null, secret secrets/db_password généré (non consigné)"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    set +e
    compose_log up -d --no-build --wait --wait-timeout 180
    status=${PIPESTATUS[0]}
    set -e
    echo "# exit: $status"
    echo "== image du conteneur api-python : $(docker inspect --format '{{.Image}}' "$(compose ps -q api-python)")"
    echo "== postgres: $(compose exec -T db postgres --version)"
    echo "== python: $(compose exec -T api-python /app/venv/bin/python --version)"
    echo "== installed:"
    compose exec -T api-python /app/venv/bin/python -c 'import importlib.metadata as m; [print(d.metadata["Name"] + "==" + d.version) for d in sorted(m.distributions(), key=lambda d: d.metadata["Name"])]'
    for path in health hello dbtest; do
      echo "== GET /$path -> $(http_get "http://127.0.0.1:5000/$path" | awk '{s=$NF; $NF=""; sub(/ $/, ""); print s, $0}')"
    done
    echo "== pytest -m \"not integration\" (hôte, $("$PYTHON" --version), pytest $("$PYTHON" -m pytest --version 2>&1 | awk '{print $2}'))"
    set +e
    "$PYTHON" -m pytest -m "not integration" -p no:cacheprovider 2>&1 | grep -v '^rootdir:'
    echo "# exit: ${PIPESTATUS[0]}"
    set -e
    echo "== base arrêtée (docker compose stop db)"
    compose_log stop db
    echo "== GET /dbtest -> $(http_get http://127.0.0.1:5000/dbtest | awk '{s=$NF; $NF=""; sub(/ $/, ""); print s, $0}')"
    echo "== log serveur (détail conservé côté serveur) :"
    compose logs --no-log-prefix api-python 2>&1 | grep -E 'ERROR in app|OperationalError' | tail -2
  } > "$OUT/app-functional.txt"
  compose down --volumes --remove-orphans >/dev/null 2>&1
  rm -rf secrets
}

gen_hardening() {
  local id api db status envsecret
  id=$(image_id)
  compose_env hardening-check
  rm -rf secrets
  {
    echo "# Validation du durcissement Compose (db + api-python, secret fichier)"
    echo "# Environnement : Docker Desktop macOS arm64 (Docker $(docker version --format '{{.Server.Version}}'), Compose $(docker compose version --short)), image $PLATFORM $IMAGE $id."
    echo "# Limite : sur Docker Desktop le propriétaire et les permissions d'un fichier monté en bind diffèrent de Linux."
    echo "#   L'exigence 0644 (lisibilité par les UID 65532 et 70) n'est donc PAS prouvée par ce run : la preuve est le run Linux de la CI."
    echo "# Variables : COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME API_IMAGE=$API_IMAGE DB_USER=$DB_USER DB_NAME=$DB_NAME, --env-file /dev/null"
    echo "# Aucune valeur de mot de passe n'est consignée (secret généré par openssl rand -hex 24, jamais affiché)."
    echo
    echo "## 1. Sans secrets/db_password : démarrage refusé (message propre à Docker Desktop)"
    echo "# date: $(now)"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build db"
    set +e
    compose_log up -d --no-build db | sed "s#/host_mnt/[^ ]*/secrets#/host_mnt/.../secrets#g" | grep -v -E 'Network|Volume|Creat'
    status=${PIPESTATUS[0]}
    set -e
    echo "# exit: $status"
    compose down --volumes --remove-orphans >/dev/null 2>&1
    echo
    echo "## 2. Secret source environment: refusé sur un service read_only"
    echo "# date: $(now)"
    echo "# note : un fichier override ne peut pas changer la source (erreur « secrets.db_password: file|environment attributes are mutually exclusive »)."
    echo "#   Copie temporaire de docker-compose.yml dans /tmp avec « file: ./secrets/db_password » remplacé par « environment: DB_PASSWORD » (supprimée ensuite)."
    echo "# cmd: DB_PASSWORD=\$(openssl rand -hex 24) docker compose --env-file /dev/null -f /tmp/compose-envsecret.yml --project-directory <repo> up -d --no-build"
    envsecret=$(mktemp /tmp/compose-envsecret.XXXX.yml)
    sed 's#file: ./secrets/db_password#environment: DB_PASSWORD#' docker-compose.yml > "$envsecret"
    set +e
    DB_PASSWORD=$(openssl rand -hex 24) compose -f "$envsecret" --project-directory "$ROOT" \
      up -d --no-build 2>&1 | grep -v 'does not match the detected host platform' \
      | grep -v -E 'Network|Volume|Creat'
    status=${PIPESTATUS[0]}
    set -e
    echo "# exit: $status"
    DB_PASSWORD=x compose -f "$envsecret" --project-directory "$ROOT" down --volumes \
      --remove-orphans >/dev/null 2>&1 || true
    rm -f "$envsecret"
    echo
    echo "## 3. Démarrage comme la CI (secret 0644, valeur non journalisée)"
    echo "# date: $(now)"
    echo "# cmd: install -d -m 0755 secrets; printf '%s' \"\$(openssl rand -hex 24)\" > secrets/db_password; chmod 0644 secrets/db_password; docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    new_secret
    set +e
    compose_log up -d --no-build --wait --wait-timeout 180 | grep Healthy
    status=${PIPESTATUS[0]}
    set -e
    echo "# exit: $status"
    echo "# cmd: docker compose ps --format ..."
    for service in api-python db; do
      echo "$service $(docker inspect --format 'state={{.State.Status}} health={{.State.Health.Status}}' "$(compose ps -q "$service")")"
    done
    api=$(compose ps -q api-python)
    db=$(compose ps -q db)
    running=$(docker inspect --format '{{.Image}}' "$api")
    echo "# image api = $IMAGE ($running) : identique à $id : $([ "$running" = "$id" ] && echo oui || echo non)"
    echo
    echo "## 4. Preuves de durcissement (docker inspect, /proc, écritures)"
    echo "# date: $(now)"
    echo "# cmd: docker inspect <conteneur> --format 'ReadonlyRootfs CapDrop SecurityOpt Memory PidsLimit User'"
    for service in api-python db; do
      echo "$service: $(docker inspect --format 'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}} PidsLimit={{.HostConfig.PidsLimit}} User={{.Config.User}}' "$(compose ps -q "$service")")"
    done
    local secret_value
    secret_value=$(cat secrets/db_password)
    echo "mot de passe (valeur) présent dans docker inspect / Config.Env : api-python=$(docker inspect "$api" | grep -q "$secret_value" && echo oui || echo non) db=$(docker inspect "$db" | grep -q "$secret_value" && echo oui || echo non)"
    local proc='
import os, sys
status = dict(l.split(":\t", 1) for l in open("/proc/1/status").read().splitlines() if ":\t" in l)
env = dict(e.split("=", 1) for e in open("/proc/1/environ").read().split("\0") if "=" in e)
print("PID 1 =", status["Name"].strip(), "| Uid:", status["Uid"].split()[0], "| CapEff:", status["CapEff"].strip(), "| NoNewPrivs:", status["NoNewPrivs"].strip())
for key in ["DB_PASSWORD", "POSTGRES_PASSWORD"]:
    print(f"{key} (hors _FILE) dans /proc/1/environ :", "oui" if key in env else "non")
if len(sys.argv) > 1 and "POSTGRES_PASSWORD" in env:
    print("valeur de POSTGRES_PASSWORD identique au secret :", "oui" if env["POSTGRES_PASSWORD"] == open(sys.argv[1]).read() else "non")
if "DB_PASSWORD_FILE" in env:
    print("DB_PASSWORD_FILE dans /proc/1/environ : oui (chemin seulement)")
'
    echo "# cmd: docker exec <api> /app/venv/bin/python -c <lecture /proc/1/status et /proc/1/environ>"
    docker exec "$api" /app/venv/bin/python -c "$proc"
    echo "# cmd: docker run --rm --platform $PLATFORM --pid=container:<db> --entrypoint /app/venv/bin/python $IMAGE -c <idem> (db n'a pas de Python ; secret monté en lecture seule sur /s pour comparaison, sans affichage)"
    set +e
    docker run --rm --platform "$PLATFORM" --pid="container:$db" --entrypoint /app/venv/bin/python \
      "$IMAGE" -c "$proc" >/dev/null 2>/tmp/proc.err
    echo "(sans --user : échec, $(grep -o 'PermissionError.*' /tmp/proc.err | head -1))"
    set -e
    rm -f /tmp/proc.err
    echo "# cmd: idem avec --user 70:70"
    docker run --rm --platform "$PLATFORM" --pid="container:$db" --user 70:70 \
      -v "$ROOT/secrets/db_password:/s:ro" --entrypoint /app/venv/bin/python "$IMAGE" -c "$proc" /s
    echo "# constat : l'entrypoint de l'image PostgreSQL lit POSTGRES_PASSWORD_FILE puis exporte POSTGRES_PASSWORD dans l'environnement du processus postgres (POSTGRES_PASSWORD_FILE n'y figure plus)."
    echo "#   Le mot de passe reste absent de docker inspect, mais PRÉSENT dans /proc/1/environ de db (lisible par l'UID 70 ou root seulement). Côté api-python il est absent."
    echo "# cmd: docker exec <api> écritures dans /app et /"
    docker exec "$api" /app/venv/bin/python -c '
import os
for p in ["/app/x", "/x"]:
    try:
        open(p, "w").close(); print(f"écriture {p} : réussie")
    except OSError as e:
        print(f"écriture {p} : échec ({e.strerror})")
s = os.stat("/run/secrets/db_password")
print("/run/secrets/db_password : lisible", "oui" if os.access("/run/secrets/db_password", os.R_OK) else "non", "mode", oct(s.st_mode & 0o777), "uid", s.st_uid, "(Docker Desktop)")
'
    echo "# cmd: docker exec <db> /usr/bin/id"
    docker exec "$db" /usr/bin/id
    echo "# cmd: docker run --network <projet>_frontend $IMAGE : résolution de db et connexion à db:5432 (isolation du réseau backend)"
    docker run --rm --platform "$PLATFORM" --network "${COMPOSE_PROJECT_NAME}_frontend" \
      --entrypoint /app/venv/bin/python "$IMAGE" -c '
import socket
try:
    socket.create_connection(("db", 5432), timeout=3)
    print("frontend -> db:5432 : connexion réussie")
except OSError as e:
    print("frontend -> db:5432 : échec (" + type(e).__name__ + ": " + str(e) + ")")
'
    echo
    echo "## 5. Tests d'intégration"
    echo "# date: $(now)"
    echo "# cmd: API_BASE_URL=http://127.0.0.1:5000 pytest -m integration tests/integration"
    set +e
    API_BASE_URL=http://127.0.0.1:5000 "$PYTHON" -m pytest -m integration -p no:cacheprovider \
      tests/integration 2>&1 | tail -1
    echo "# exit: ${PIPESTATUS[0]}"
    set -e
    echo
    echo "## 6. Persistance du volume db-data"
    echo "# date: $(now)"
    echo "# cmd: docker compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -c 'create table persist(v int); insert into persist values (42);'"
    compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db \
      -c 'create table persist(v int); insert into persist values (42);'
    echo "# exit: $?"
    echo "# cmd: docker compose --env-file /dev/null down (sans -v)"
    compose_log down | grep Removed
    echo "# exit: ${PIPESTATUS[0]}"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    set +e
    compose_log up -d --no-build --wait --wait-timeout 180 | grep Healthy
    echo "# exit: ${PIPESTATUS[0]}"
    set -e
    echo "# cmd: docker compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -At -c 'select v from persist'"
    echo "select v from persist -> $(compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -At -c 'select v from persist')"
    echo
    echo "## 7. Nettoyage"
    echo "# date: $(now)"
    echo "# cmd: docker compose --env-file /dev/null down --volumes --remove-orphans; rm -rf secrets"
    compose_log down --volumes --remove-orphans | grep Removed
    echo "# exit: ${PIPESTATUS[0]}"
    rm -rf secrets
    echo "# résidus : conteneurs=$(docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" | wc -l | tr -d ' ') volumes=$(docker volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" | wc -l | tr -d ' ') secrets/=$([ -e secrets ] && echo présent || echo absent)"
  } > "$OUT/compose-hardening.txt"
}

steps=("$@")
[ ${#steps[@]} -eq 0 ] && steps=(all)
[ "${steps[0]}" = all ] && steps=(image dive trivy run compat dockerignore cache functional hardening)
build
for step in "${steps[@]}"; do
  case "$step" in
    image) gen_image ;;
    dive) gen_dive ;;
    trivy) gen_trivy ;;
    run) gen_run ;;
    compat) gen_compat ;;
    dockerignore) gen_dockerignore ;;
    cache) gen_cache ;;
    functional) gen_functional ;;
    hardening) gen_hardening ;;
    *) echo "étape inconnue : $step" >&2; exit 2 ;;
  esac
  echo "$step : $OUT ($(now))"
done
