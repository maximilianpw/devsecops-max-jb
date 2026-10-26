#!/usr/bin/env bash
# Régénère les preuves de evidence/after/ liées à l'image, sur une seule image
# construite comme en CI (linux/amd64, sans attestations).
#
# Usage (depuis la racine du dépôt, Docker démarré) :
#   scripts/evidence/regenerate.sh [all|image|dive|dive-db|trivy|run|compat|dockerignore|cache|functional|hardening]...
# Sur TP2 : sans argument, ou avec build/run/scan, délégation au parcours TP2.
# Les étapes propres au TP1 rejouent sa révision historique dans un temporaire.
# --tp1 sélectionne explicitement ce parcours (notamment pour run seul).
#
# Prérequis : Docker avec Compose v2 et BuildKit, Dive 0.13.1, Trivy 0.75.0,
# Python 3.15 avec requirements-dev.txt (variable PYTHON, défaut python3).
# Les fichiers flake8.txt et hadolint.txt ne dépendent pas de l'image et ne
# sont pas régénérés ici (hadolint.txt : scripts/evidence/hadolint.sh).
#
# Garanties du parcours historique (sans docker-bake.hcl) :
# - le dépôt n'est pas modifié hors de evidence/after/ : le secret de la base
#   est généré dans un répertoire temporaire et fourni à Compose par un
#   fichier override ; le répertoire secrets/ de l'utilisateur n'est pas lu ;
# - conteneurs, volumes, réseaux et fichiers temporaires sont supprimés à la
#   sortie, y compris sur erreur ou interruption ;
# - chaque résultat attendu est vérifié : le script échoue (code 1) si l'un
#   d'eux ne l'est pas, après avoir écrit les preuves ;
# - aucune valeur de mot de passe n'est écrite dans les preuves.
set -euo pipefail

if [ -f docker-bake.hcl ]; then
  case "${1:-}" in
    --tp1) shift ;;
    all|image|dive|dive-db|trivy|compat|dockerignore|cache|functional|hardening) ;;
    *) exec scripts/evidence/tp2.sh "$@" ;;
  esac
  # Les mesures TP1 doivent garder leur Dockerfile, pas celui du TP2 qui exige
  # un secret de build. Ne pas écraser les preuves historiques déjà versionnées.
  tp1_commit=33e67287c9c02dc0b5da67a75d40e46d2c81c45d
  tp1_work=$(mktemp -d)
  trap 'rm -rf "$tp1_work"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  git archive "$tp1_commit" | tar -x -C "$tp1_work" --exclude=evidence/after
  # Le contrôle historique du contexte doit aussi pouvoir exclure un .git.
  git -C "$tp1_work" init --quiet
  mkdir -p "$tp1_work/evidence/after" evidence/tp1
  tp1_out=$(mktemp -d "$PWD/evidence/tp1/replay-XXXXXXXX")
  printf '%s\n' "$tp1_commit" > "$tp1_out/revision.txt"
  rc=0
  (cd "$tp1_work" && bash scripts/evidence/regenerate.sh "$@") || rc=$?
  cp -R "$tp1_work/evidence/after/." "$tp1_out/"
  printf 'Preuves TP1 : %s\n' "$tp1_out"
  exit "$rc"
fi

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
RUN_CONTAINER=evidence-run
CACHE_IMAGE=flask-api:cachetest

WORK=$(mktemp -d)
chmod 0755 "$WORK"
SECRET=$WORK/secrets/db_password
OVERRIDE=$WORK/compose.override.yml
printf 'secrets:\n  db_password:\n    file: %s\n' "$SECRET" > "$OVERRIDE"
PROJECTS=""
RUN_ID=""
CACHE_CREATED=""
FAILURES=""

cleanup() {
  local rc=$? project left
  trap - EXIT INT TERM
  for project in $PROJECTS; do
    COMPOSE_PROJECT_NAME=$project docker compose --env-file /dev/null \
      -f docker-compose.yml -f "$OVERRIDE" down --volumes --remove-orphans >/dev/null 2>&1 \
      || FAILURES="$FAILURES\n- nettoyage : docker compose down a échoué ($project)"
    left=$(residues "$project") || left="inventaire Docker en échec"
    [ "$left" = "0 0 0" ] \
      || FAILURES="$FAILURES\n- nettoyage : ressources restantes pour $project (conteneurs volumes réseaux : $left)"
  done
  # Seules les ressources créées par cette exécution sont supprimées.
  # Conteneur supprimé par son identifiant, obtenu de sa propre création.
  if [ -n "$RUN_ID" ]; then
    docker rm -f "$RUN_ID" >/dev/null 2>&1 \
      || FAILURES="$FAILURES\n- nettoyage : suppression du conteneur $RUN_CONTAINER"
  fi
  if [ -n "$CACHE_CREATED" ]; then
    docker image rm "$CACHE_IMAGE" >/dev/null 2>&1 \
      || FAILURES="$FAILURES\n- nettoyage : suppression de l'image $CACHE_IMAGE"
  fi
  rm -rf "$WORK"
  if [ -n "$FAILURES" ]; then
    printf 'Résultat inattendu :%b\n' "$FAILURES" >&2
    [ "$rc" -eq 0 ] && rc=1
  fi
  exit "$rc"
}
# Ressources Docker d'un projet Compose : « conteneurs volumes réseaux ».
# Code retour non nul si l'un des inventaires échoue.
residues() {
  local filter="label=com.docker.compose.project=$1" containers volumes networks
  containers=$(docker ps -aq --filter "$filter") || return 1
  volumes=$(docker volume ls -q --filter "$filter") || return 1
  networks=$(docker network ls -q --filter "$filter") || return 1
  echo "$(count_lines "$containers") $(count_lines "$volumes") $(count_lines "$networks")"
}
count_lines() { if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Enregistre un écart entre un résultat obtenu et le résultat attendu.
expect() { # expect <contrôle> <attendu> <obtenu>
  [ "$2" = "$3" ] || FAILURES="$FAILURES\n- $1 : obtenu « $3 », attendu « $2 »"
}
expect_failure() { # expect_failure <contrôle> <code retour>
  [ "$2" -ne 0 ] || FAILURES="$FAILURES\n- $1 : réussite inattendue"
}

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g'; }
image_id() { docker image inspect --format '{{.Id}}' "$IMAGE"; }
# Python de l'image finale (pas de shell dans l'image).
in_image() { docker run --rm --platform "$PLATFORM" --entrypoint /app/venv/bin/python "$IMAGE" -c "$1"; }
trivy_header() {
  echo "# Version: $("$TRIVY" --version | sed -n 's/^Version: //p')"
  "$TRIVY" --version | sed -n '/Vulnerability DB/,$p' | sed 's/^/# /'
}
# Exécute une commande, affiche sa sortie et son code ; le code est dans RC.
run() {
  RC=0
  "$@" > "$WORK/out" 2>&1 || RC=$?
  cat "$WORK/out"
  echo "# exit: $RC"
}

# Exécute une commande depuis le répertoire de travail (chemins courts dans les preuves).
in_work() { (cd "$WORK" && "$@"); }

build() {
  docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
    --load -t "$IMAGE" . >/dev/null 2>&1
  echo "image construite : $IMAGE $(image_id)"
}

gen_image() {
  local id size rc=0
  id=$(image_id)
  "$DIVE" "$IMAGE" --json "$WORK/dive.json" >/dev/null 2>&1
  size=$("$PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"]["sizeBytes"])' "$WORK/dive.json")
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
    docker run --rm --platform "$PLATFORM" --entrypoint /bin/sh "$IMAGE" -c 'echo shell' 2>&1 || rc=$?
    echo "exit: $rc"
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
  expect_failure "image : shell absent" "$rc"
  expect "image : utilisateur" "65532:65532" "$(docker image inspect --format '{{.Config.User}}' "$IMAGE")"
}

gen_dive() {
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: dive --ci --ci-config .dive-ci $IMAGE (commande de la CI)"
    run "$DIVE" --ci --ci-config .dive-ci "$IMAGE" | strip_ansi
  } > "$OUT/dive.txt"
  expect "Dive API" "# exit: 0" "$(grep '^# exit:' "$OUT/dive.txt")"
}

# Mesure Dive de l'image PostgreSQL (non bloquante en CI) : taille et efficacité.
gen_dive_db() {
  docker pull -q --platform "$PLATFORM" "$DB_IMAGE" >/dev/null
  docker save --platform "$PLATFORM" -o "$WORK/db.tar" "$DB_IMAGE"
  "$DIVE" --source docker-archive "$WORK/db.tar" --json "$WORK/db.json" >/dev/null 2>&1
  {
    echo "# date: $(now)"
    echo "# image: $DB_IMAGE ($PLATFORM)"
    echo "# cmd: docker save --platform $PLATFORM -o db.tar <image> ; dive --source docker-archive db.tar --json db.json"
    "$PYTHON" - "$WORK/db.json" <<'PY'
import json, sys
image = json.load(open(sys.argv[1]))["image"]
print("size_bytes=" + str(image["sizeBytes"]))
print("size_MB=%.1f (10^6 octets)" % (image["sizeBytes"] / 1e6))
print("efficiency=%.4f %%" % (image["efficiencyScore"] * 100))
print("wasted_bytes=" + str(image["inefficientBytes"]))
PY
  } > "$OUT/dive-db.txt"
}

gen_trivy() {
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: trivy image --platform $PLATFORM $IMAGE (toutes sévérités)"
    trivy_header
    run "$TRIVY" image -q --platform "$PLATFORM" "$IMAGE"
    expect "Trivy API (toutes sévérités)" 0 "$RC"
    echo
    echo "## gate HIGH/CRITICAL corrigibles (commande de la CI, sur l'archive docker save)"
    echo "# date: $(now)"
    echo "# cmd: trivy image --input image.tar --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table"
    docker save -o "$WORK/image.tar" "$IMAGE"
    run in_work "$TRIVY" image -q --input image.tar --scanners vuln --skip-db-update \
      --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table
    expect "gate Trivy API" 0 "$RC"
  } > "$OUT/trivy.txt"
  {
    echo "# date: $(now)"
    echo "# cmd: trivy image --image-src remote --platform $PLATFORM $DB_IMAGE (toutes sévérités)"
    trivy_header
    run "$TRIVY" image -q --image-src remote --platform "$PLATFORM" "$DB_IMAGE"
    expect "Trivy PostgreSQL (toutes sévérités)" 0 "$RC"
    echo
    echo "## gate HIGH/CRITICAL corrigibles"
    echo "# date: $(now)"
    echo "# cmd: trivy image --image-src remote --platform $PLATFORM --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table $DB_IMAGE"
    run "$TRIVY" image -q --image-src remote --platform "$PLATFORM" --scanners vuln \
      --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
      --format table "$DB_IMAGE"
    expect "gate Trivy PostgreSQL" 0 "$RC"
  } > "$OUT/trivy-db.txt"
  {
    echo "# date: $(now)"
    echo "# cmd: trivy fs --scanners vuln requirements.txt"
    trivy_header
    run "$TRIVY" fs -q --scanners vuln requirements.txt
    expect "Trivy requirements.txt (toutes sévérités)" 0 "$RC"
    echo
    echo "## gate HIGH/CRITICAL corrigibles"
    echo "# cmd: trivy fs --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table requirements.txt"
    run "$TRIVY" fs -q --scanners vuln --skip-db-update --severity HIGH,CRITICAL \
      --ignore-unfixed --exit-code 1 --format table requirements.txt
    expect "gate Trivy requirements.txt" 0 "$RC"
  } > "$OUT/trivy-deps.txt"
}

http_get() { # affiche « corps code »
  "$PYTHON" - "$1" <<'PY'
import sys, urllib.error, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as r:
        status, body = r.status, r.read().decode()
except urllib.error.HTTPError as e:
    status, body = e.code, e.read().decode()
except OSError as e:
    status, body = 0, type(e).__name__
print(body.strip(), status)
PY
}
http_status() { http_get "$1" | awk '{print $NF}'; }

wait_health() {
  local _
  for _ in $(seq 1 30); do
    [ "$(http_status "$1")" = 200 ] && return 0
    sleep 1
  done
  return 1
}

gen_run() {
  local path body
  RUN_ID=$(docker run -d --name "$RUN_CONTAINER" --platform "$PLATFORM" --read-only \
    --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:5051:5000 "$IMAGE")
  wait_health http://127.0.0.1:5051/health
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# cmd: docker run --read-only --cap-drop ALL --security-opt no-new-privileges -p 127.0.0.1:5051:5000 $IMAGE (sans base de données)"
    for path in health hello dbtest; do
      body=$(http_get "http://127.0.0.1:5051/$path")
      echo "GET /$path -> $body"
      echo "$path ${body##* }" >> "$WORK/run.status"
    done
    sleep 1
    echo "## journaux"
    docker logs "$RUN_ID" 2>&1 | grep -v '"GET ' | head -6
  } > "$OUT/image-run.txt"
  expect "image seule : codes HTTP" "health 200 hello 200 dbtest 500" "$(tr '\n' ' ' < "$WORK/run.status" | sed 's/ $//')"
  docker rm -f "$RUN_ID" >/dev/null
  RUN_ID=""
}

gen_compat() {
  local info rc=0 builder runtime
  info='import platform, sysconfig; abi = sysconfig.get_config_var("SOABI").split("-"); print("python", platform.python_version(), "abi", abi[0] + "-" + abi[1], "arch", platform.machine(), "libc", platform.libc_ver())'
  builder=$(docker run --rm --platform "$PLATFORM" --entrypoint python "$BUILDER" -c "$info")
  runtime=$(in_image "$info")
  {
    echo "# date: $(now)"
    echo "# image: $IMAGE $(image_id)"
    echo "# compatibilité builder / runtime ($PLATFORM)"
    echo "builder: $builder"
    echo "runtime: $runtime"
    in_image '
import os, psycopg2, psycopg2.extensions as e, sysconfig
print("psycopg2", psycopg2.__version__, "libpq", e.libpq_version())
libs = os.path.join(os.path.dirname(os.path.dirname(psycopg2.__file__)), "psycopg2_binary.libs")
print("bibliothèques embarquées par psycopg2-binary:", sorted(os.listdir(libs)))
d = sysconfig.get_config_var("WHEEL_PKG_DIR")
print("WHEEL_PKG_DIR", d, sorted(os.listdir(d)) if d and os.path.isdir(d) else "absent")
'
    docker run --rm --platform "$PLATFORM" --entrypoint /app/venv/bin/python "$IMAGE" \
      -m ensurepip >/dev/null 2>&1 || rc=$?
    echo "# python -m ensurepip dans le runtime : échec (aucun site-packages accessible en écriture), exit: $rc"
  } > "$OUT/runtime-compat.txt"
  expect "compatibilité builder / runtime" "$builder" "$runtime"
  expect_failure "ensurepip dans le runtime" "$rc"
}

# Copie du dépôt (avec .git) sans le répertoire secrets/ de l'utilisateur.
copy_repo() {
  mkdir -p "$1"
  tar -C "$ROOT" --exclude ./secrets -cf - . | tar -C "$1" -xf -
}

gen_dockerignore() {
  local repo=$WORK/dockerignore-repo
  copy_repo "$repo"
  (
    cd "$repo"
    mkdir -p .venv __pycache__ .pytest_cache htmlcov logs
    for f in .coverage .env .env.local backup.tar.gz debug.log dump.zip notes.md \
             secrets.json server.key logs/app.log; do
      echo parasite > "$f"
    done
    printf 'FROM %s\nCOPY . /ctx\nRUN find /ctx -mindepth 1 | sort\n' "$BUILDER" > "$WORK/Dockerfile.ctx"
    {
      echo "# date: $(now)"
      echo "# contrôle du .dockerignore : copie du dépôt (avec .git) dans laquelle des fichiers parasites ont été ajoutés, puis build d'un Dockerfile de test qui liste le contexte reçu"
      echo "## contenu du dossier"
      "$PYTHON" -c 'import os; print(" ".join(sorted(os.listdir("."), key=str.lower)))'
      echo "## Dockerfile de test"
      sed 's/^/    /' "$WORK/Dockerfile.ctx"
      echo "## fichiers reçus par le build"
      docker buildx build --platform "$PLATFORM" --no-cache --progress=plain \
        -f "$WORK/Dockerfile.ctx" . 2>&1 | sed -n 's/^#[0-9]* [0-9.]* \(\/ctx\/.*\)$/\1/p'
    } > "$ROOT/$OUT/dockerignore.txt"
  )
  expect ".dockerignore : contexte reçu" "/ctx/app.py /ctx/requirements.txt" \
    "$(sed -n '/^## fichiers reçus/,$p' "$OUT/dockerignore.txt" | sed 1d | tr '\n' ' ' | sed 's/ $//')"
}

gen_cache() {
  local repo=$WORK/cache-repo ref copy_id
  copy_repo "$repo"
  ref=$(image_id)
  docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
    --load -t "$CACHE_IMAGE" "$repo" >/dev/null 2>&1
  CACHE_CREATED=1
  copy_id=$(docker image inspect --format '{{.Id}}' "$CACHE_IMAGE")
  echo "# modification de test" >> "$repo/app.py"
  {
    echo "# date: $(now) (fin du test ; copie du dépôt dans un répertoire temporaire, app.py du dépôt non modifié)"
    echo "# image de référence : $IMAGE $ref (build de la copie avant modification identique : $([ "$copy_id" = "$ref" ] && echo oui || echo "non, $copy_id"))"
    echo "# contrôle du cache : rebuild après modification de app.py seul"
    echo "# cmd: docker buildx build --platform $PLATFORM --provenance=false --sbom=false --load --progress=plain -t $CACHE_IMAGE ."
    docker buildx build --platform "$PLATFORM" --provenance=false --sbom=false \
      --load --progress=plain -t "$CACHE_IMAGE" "$repo" 2>&1 \
      | grep -E '^#[0-9]+ (\[|CACHED)'
  } > "$OUT/build-cache.txt"
  expect "cache : image de la copie identique" "$ref" "$copy_id"
  expect "cache : installation des dépendances en cache" "CACHED" \
    "$(grep -A1 'builder 4/4\] RUN' "$OUT/build-cache.txt" | sed -n 2p | awk '{print $2}')"
  docker image rm "$CACHE_IMAGE" >/dev/null
  CACHE_CREATED=""
}

# Stack Compose comme en CI : image auditée, identifiants de test, secret
# fichier généré dans le répertoire temporaire (override Compose).
compose_env() {
  export COMPOSE_PROJECT_NAME=$1 API_IMAGE=$IMAGE DB_USER=ci_user DB_NAME=ci_db
  export COMPOSE_FILE="docker-compose.yml:$OVERRIDE"
  PROJECTS="$PROJECTS $1"
}
new_secret() {
  install -d -m 0755 "$(dirname "$SECRET")"
  openssl rand -hex 24 | tr -d '\n' > "$SECRET"
  chmod 0644 "$SECRET"
}
compose() { docker compose --env-file /dev/null "$@"; }
# Sortie de docker compose sans l'avertissement de plateforme propre à l'hôte
# arm64 ; le code retour est celui de docker compose.
compose_log() {
  local rc=0
  compose "$@" > "$WORK/compose.out" 2>&1 || rc=$?
  grep -v 'does not match the detected host platform' "$WORK/compose.out" | sed "s#$WORK#<tmp>#g" || true
  return "$rc"
}
pkg_list='import importlib.metadata as m; [print(d.metadata["Name"] + "==" + d.version) for d in sorted(m.distributions(), key=lambda d: d.metadata["Name"])]'

gen_functional() {
  local id rc path body
  id=$(image_id)
  compose_env functional-check
  new_secret
  {
    echo "# date: $(now)"
    echo "# contrôle fonctionnel : image $IMAGE $id ($PLATFORM, Docker Desktop macOS arm64) servie par gunicorn dans la stack docker-compose.yml réelle"
    echo "# variables : COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME API_IMAGE=$API_IMAGE DB_USER=$DB_USER DB_NAME=$DB_NAME, --env-file /dev/null ; secret généré dans un répertoire temporaire (non consigné), fourni par un override Compose"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    rc=0; compose_log up -d --no-build --wait --wait-timeout 180 || rc=$?
    echo "# exit: $rc"
    expect "fonctionnel : démarrage" 0 "$rc"
    echo "== image du conteneur api-python : $(docker inspect --format '{{.Image}}' "$(compose ps -q api-python)")"
    echo "== postgres: $(compose exec -T db postgres --version)"
    echo "== python: $(compose exec -T api-python /app/venv/bin/python --version)"
    echo "== installed:"
    compose exec -T api-python /app/venv/bin/python -c "$pkg_list"
    for path in health hello dbtest; do
      body=$(http_get "http://127.0.0.1:5000/$path")
      echo "== GET /$path -> ${body##* } ${body% *}"
      expect "fonctionnel : GET /$path" 200 "${body##* }"
    done
    echo "== pytest -m \"not integration\" (hôte, $("$PYTHON" --version), pytest $("$PYTHON" -m pytest --version 2>&1 | awk '{print $2}'))"
    rc=0
    "$PYTHON" -m pytest -m "not integration" -p no:cacheprovider > "$WORK/pytest.out" 2>&1 || rc=$?
    grep -v '^rootdir:' "$WORK/pytest.out"
    echo "# exit: $rc"
    expect "fonctionnel : tests unitaires" 0 "$rc"
    echo "== base arrêtée (docker compose stop db)"
    compose_log stop db
    body=$(http_get http://127.0.0.1:5000/dbtest)
    echo "== GET /dbtest -> ${body##* } ${body% *}"
    expect "fonctionnel : GET /dbtest sans base" 500 "${body##* }"
    echo "== log serveur (détail conservé côté serveur) :"
    compose logs --no-log-prefix api-python 2>&1 | grep -E 'ERROR in app|OperationalError' | tail -2
  } > "$OUT/app-functional.txt"
  compose down --volumes --remove-orphans >/dev/null 2>&1
  rm -f "$SECRET"
}

gen_hardening() {
  local id api db rc running secret_value proc left
  id=$(image_id)
  compose_env hardening-check
  rm -f "$SECRET"
  {
    echo "# Validation du durcissement Compose (db + api-python, secret fichier)"
    echo "# Environnement : Docker Desktop macOS arm64 (Docker $(docker version --format '{{.Server.Version}}'), Compose $(docker compose version --short)), image $PLATFORM $IMAGE $id."
    echo "# Limite : sur Docker Desktop le propriétaire et les permissions d'un fichier monté en bind diffèrent de Linux."
    echo "#   L'exigence 0644 (lisibilité par les UID 65532 et 70) n'est donc PAS prouvée par ce run : la preuve est le run Linux de la CI."
    echo "# Variables : COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME API_IMAGE=$API_IMAGE DB_USER=$DB_USER DB_NAME=$DB_NAME, --env-file /dev/null"
    echo "# Secret : fichier db_password d'un répertoire temporaire du script, fourni par un override Compose (secrets.db_password.file) ; secrets/ du dépôt non utilisé."
    echo "# Aucune valeur de mot de passe n'est consignée (secret généré par openssl rand -hex 24, jamais affiché)."
    echo
    echo "## 1. Sans fichier secret : démarrage refusé (message propre à Docker Desktop)"
    echo "# date: $(now)"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build db"
    rc=0; compose_log up -d --no-build db > "$WORK/s1.out" || rc=$?
    sed "s#/host_mnt/[^ ]*/secrets#/host_mnt/.../secrets#g" "$WORK/s1.out" | grep -v -E 'Network|Volume|Creat' || true
    echo "# exit: $rc"
    expect_failure "durcissement : démarrage sans secret" "$rc"
    compose down --volumes --remove-orphans >/dev/null 2>&1
    echo
    echo "## 2. Secret source environment: refusé sur un service read_only"
    echo "# date: $(now)"
    echo "# note : un fichier override ne peut pas changer la source (erreur « secrets.db_password: file|environment attributes are mutually exclusive »)."
    echo "#   Copie temporaire de docker-compose.yml avec « file: ./secrets/db_password » remplacé par « environment: DB_PASSWORD » (supprimée ensuite)."
    echo "# cmd: DB_PASSWORD=\$(openssl rand -hex 24) docker compose --env-file /dev/null -f <copie> --project-directory <repo> up -d --no-build"
    sed 's#file: ./secrets/db_password#environment: DB_PASSWORD#' docker-compose.yml > "$WORK/compose-envsecret.yml"
    rc=0
    DB_PASSWORD=$(openssl rand -hex 24) COMPOSE_FILE='' compose -f "$WORK/compose-envsecret.yml" \
      --project-directory "$ROOT" up -d --no-build > "$WORK/s2.out" 2>&1 || rc=$?
    grep -v -E 'does not match the detected host platform|Network|Volume|Creat' "$WORK/s2.out" | sed "s#$WORK#<tmp>#g" || true
    echo "# exit: $rc"
    expect_failure "durcissement : secret environment sur service read_only" "$rc"
    DB_PASSWORD=x COMPOSE_FILE='' compose -f "$WORK/compose-envsecret.yml" --project-directory "$ROOT" \
      down --volumes --remove-orphans >/dev/null 2>&1 || true
    echo
    echo "## 3. Démarrage comme la CI (secret 0644, valeur non journalisée)"
    echo "# date: $(now)"
    echo "# cmd: openssl rand -hex 24 > <tmp>/secrets/db_password ; chmod 0644 ; docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    new_secret
    rc=0; compose_log up -d --no-build --wait --wait-timeout 180 > "$WORK/s3.out" || rc=$?
    grep Healthy "$WORK/s3.out" || true
    echo "# exit: $rc"
    expect "durcissement : démarrage avec secret" 0 "$rc"
    echo "# cmd: docker compose ps --format ..."
    for service in api-python db; do
      echo "$service $(docker inspect --format 'state={{.State.Status}} health={{.State.Health.Status}}' "$(compose ps -q "$service")")"
      expect "durcissement : $service healthy" healthy \
        "$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q "$service")")"
    done
    api=$(compose ps -q api-python)
    db=$(compose ps -q db)
    running=$(docker inspect --format '{{.Image}}' "$api")
    echo "# image api = $IMAGE ($running) : identique à $id : $([ "$running" = "$id" ] && echo oui || echo non)"
    expect "durcissement : image auditée" "$id" "$running"
    echo
    echo "## 4. Preuves de durcissement (docker inspect, /proc, écritures)"
    echo "# date: $(now)"
    echo "# cmd: docker inspect <conteneur> --format 'ReadonlyRootfs CapDrop SecurityOpt Memory PidsLimit User'"
    for service in api-python db; do
      echo "$service: $(docker inspect --format 'ReadonlyRootfs={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} Memory={{.HostConfig.Memory}} PidsLimit={{.HostConfig.PidsLimit}} User={{.Config.User}}' "$(compose ps -q "$service")")"
      expect "durcissement : $service lecture seule et sans capability" "true [ALL] [no-new-privileges:true]" \
        "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' "$(compose ps -q "$service")")"
    done
    secret_value=$(cat "$SECRET")
    echo "mot de passe (valeur) présent dans docker inspect / Config.Env : api-python=$(docker inspect "$api" | grep -q "$secret_value" && echo oui || echo non) db=$(docker inspect "$db" | grep -q "$secret_value" && echo oui || echo non)"
    proc='
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
    docker exec "$api" /app/venv/bin/python -c "$proc" | tee "$WORK/proc-api.out"
    echo "# cmd: docker run --rm --platform $PLATFORM --pid=container:<db> --entrypoint /app/venv/bin/python $IMAGE -c <idem> (db n'a pas de Python ; secret monté en lecture seule sur /s pour comparaison, sans affichage)"
    docker run --rm --platform "$PLATFORM" --pid="container:$db" --entrypoint /app/venv/bin/python \
      "$IMAGE" -c "$proc" >/dev/null 2>"$WORK/proc.err" || true
    echo "(sans --user : échec, $(grep -o 'PermissionError.*' "$WORK/proc.err" | head -1))"
    echo "# cmd: idem avec --user 70:70"
    docker run --rm --platform "$PLATFORM" --pid="container:$db" --user 70:70 \
      -v "$SECRET:/s:ro" --entrypoint /app/venv/bin/python "$IMAGE" -c "$proc" /s | tee "$WORK/proc-db.out"
    expect "durcissement : CapEff/NoNewPrivs api et db" "1 1" \
      "$(grep -c 'CapEff: 0000000000000000 | NoNewPrivs: 1' "$WORK/proc-api.out") $(grep -c 'CapEff: 0000000000000000 | NoNewPrivs: 1' "$WORK/proc-db.out")"
    expect "durcissement : mot de passe absent de l'environnement de l'API" 0 \
      "$(grep -c '_PASSWORD (hors _FILE) dans /proc/1/environ : oui' "$WORK/proc-api.out" || true)"
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
' | tee "$WORK/write.out"
    expect "durcissement : écritures refusées" 0 "$(grep -c 'réussie' "$WORK/write.out" || true)"
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
' | tee "$WORK/isolation.out"
    expect "durcissement : isolation frontend -> db" 0 "$(grep -c 'connexion réussie' "$WORK/isolation.out" || true)"
    echo
    echo "## 5. Tests d'intégration"
    echo "# date: $(now)"
    echo "# cmd: API_BASE_URL=http://127.0.0.1:5000 pytest -m integration tests/integration"
    rc=0
    API_BASE_URL=http://127.0.0.1:5000 "$PYTHON" -m pytest -m integration -p no:cacheprovider \
      tests/integration > "$WORK/integration.out" 2>&1 || rc=$?
    tail -1 "$WORK/integration.out"
    echo "# exit: $rc"
    expect "durcissement : tests d'intégration" 0 "$rc"
    echo
    echo "## 6. Persistance du volume db-data"
    echo "# date: $(now)"
    echo "# cmd: docker compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -c 'create table persist(v int); insert into persist values (42);'"
    run compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db \
      -c 'create table persist(v int); insert into persist values (42);'
    expect "persistance : initialisation SQL" 0 "$RC"
    echo "# cmd: docker compose --env-file /dev/null down (sans -v)"
    rc=0; compose_log down > "$WORK/down.out" || rc=$?
    grep Removed "$WORK/down.out" || true
    echo "# exit: $rc"
    expect "persistance : arrêt de la stack" 0 "$rc"
    expect "persistance : conteneurs supprimés, volume conservé" "0 1" \
      "$( (residues "$COMPOSE_PROJECT_NAME" || echo "inventaire Docker en échec") | cut -d' ' -f1-2)"
    echo "# cmd: docker compose --env-file /dev/null up -d --no-build --wait --wait-timeout 180"
    rc=0; compose_log up -d --no-build --wait --wait-timeout 180 > "$WORK/up.out" || rc=$?
    grep Healthy "$WORK/up.out" || true
    echo "# exit: $rc"
    expect "persistance : redémarrage de la stack" 0 "$rc"
    echo "# conteneur db recréé : $([ "$(compose ps -q db)" != "$db" ] && echo oui || echo non)"
    expect "persistance : conteneur db recréé" oui "$([ "$(compose ps -q db)" != "$db" ] && echo oui || echo non)"
    echo "# cmd: docker compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -At -c 'select v from persist'"
    secret_value=$(compose exec -T db /usr/bin/psql -h /tmp -U ci_user -d ci_db -At -c 'select v from persist')
    echo "select v from persist -> $secret_value"
    expect "durcissement : persistance" 42 "$secret_value"
    echo
    echo "## 7. Nettoyage"
    echo "# date: $(now)"
    echo "# cmd: docker compose --env-file /dev/null down --volumes --remove-orphans ; suppression du secret temporaire"
    rc=0; compose_log down --volumes --remove-orphans > "$WORK/clean.out" || rc=$?
    grep Removed "$WORK/clean.out" || true
    echo "# exit: $rc"
    expect "nettoyage : docker compose down" 0 "$rc"
    rm -f "$SECRET"
    left=$(residues "$COMPOSE_PROJECT_NAME") || left="inventaire Docker en échec"
    echo "# résidus (conteneurs volumes réseaux) : $left ; secret temporaire : $([ -e "$SECRET" ] && echo présent || echo absent)"
    expect "nettoyage : résidus" "0 0 0" "$left"
  } > "$OUT/compose-hardening.txt"
}

steps=("$@")
[ ${#steps[@]} -eq 0 ] && steps=(all)
[ "${steps[0]}" = all ] && steps=(image dive dive-db trivy run compat dockerignore cache functional hardening)
for step in "${steps[@]}"; do
  case "$step" in
    image|dive|dive-db|trivy|run|compat|dockerignore|cache|functional|hardening) ;;
    *) echo "étape inconnue : $step" >&2; exit 2 ;;
  esac
done
# Les noms des ressources figurent dans les preuves : plutôt que de supprimer
# une ressource homonyme préexistante, le script s'arrête sans rien toucher.
for step in "${steps[@]}"; do
  case "$step" in
    run) resource="conteneur $RUN_CONTAINER"
         found=$(docker ps -aq --filter "name=^${RUN_CONTAINER}\$") \
           || { echo "inventaire Docker en échec ($resource) : abandon." >&2; exit 2; }
         [ -z "$found" ] ;;
    cache) resource="image $CACHE_IMAGE"
           found=$(docker images -q "$CACHE_IMAGE") \
             || { echo "inventaire Docker en échec ($resource) : abandon." >&2; exit 2; }
           [ -z "$found" ] ;;
    functional|hardening)
      project=$([ "$step" = functional ] && echo functional-check || echo hardening-check)
      resource="projet Compose $project"
      left=$(residues "$project") \
        || { echo "inventaire Docker en échec pour $project : abandon." >&2; exit 2; }
      [ "$left" = "0 0 0" ] ;;
    *) true ;;
  esac || { echo "$resource déjà présent : supprimez-le avant de régénérer les preuves." >&2; exit 2; }
done
build
for step in "${steps[@]}"; do
  case "$step" in
    dive-db) gen_dive_db ;;
    *) "gen_$step" ;;
  esac
  echo "$step : $OUT ($(now))"
done
