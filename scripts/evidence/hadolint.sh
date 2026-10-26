#!/usr/bin/env bash
# Régénère evidence/after/hadolint.txt : Hadolint sur le Dockerfile, politique
# d'équipe (check_hadolint_policy.py), mutations de .hadolint.yaml, limites de
# Hadolint et contrôles qui les couvrent, lecture du Dockerfile par
# check_pinning.py comparée à BuildKit.
#
# Usage (depuis la racine du dépôt, Docker démarré, Hadolint 2.15.1) :
#   scripts/evidence/hadolint.sh > evidence/after/hadolint.txt 2>&1
# Variable PYTHON : interpréteur utilisé (défaut python3).
set -u
PY=${PYTHON:-python3}
C=scripts/ci/check_hadolint_policy.py
# Instruction FROM de l'étape finale du Dockerfile (image épinglée par digest).
B="FROM $(sed -n "s/^FROM \([^ ]*\)$/\1/p" Dockerfile)"
echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# $(hadolint --version)"
echo "# cmd: hadolint --config .hadolint.yaml Dockerfile"
hadolint --no-color --config .hadolint.yaml Dockerfile; echo "exit: $?"
echo
echo "# cmd: python3 $C"
echo "# format et invariants de .hadolint.yaml, puis règles d'équipe R1-R6 rejouées"
echo "# sur des Dockerfiles qui ne violent chacun que la règle visée (non versionnés)"
$PY $C; echo "exit: $?"
echo
echo "# mutations de .hadolint.yaml (copie temporaire) : le contrôle doit échouer"
d=$(mktemp -d)
mut() {
  echo "## $1"
  $PY $C --config "$d/.hadolint.yaml" 2>&1 >/dev/null | sed "s#$d/##"
  echo "exit: ${PIPESTATUS[0]}"
}
s() { sed "$1" .hadolint.yaml > "$d/.hadolint.yaml"; mut "$2"; }
a() { { cat .hadolint.yaml; printf '%s\n' "$1"; } > "$d/.hadolint.yaml"; mut "$2"; }
s 's/    - DL3025.*//' "règle d'équipe retirée (DL3025)"
s 's/DL3042/DL3O42/' "code mal saisi (DL3O42)"
a "    - 'DL3008'" "règle ajoutée entre guillemets"
a "    - DL3008" "règle ajoutée sans cas de test"
s 's/disable-ignore-pragma: true/disable-ignore-pragma: false/' "pragmas autorisés"
s 's/disable-ignore-pragma/disable-ignore-pragmas/' "clé mal saisie"
s 's/failure-threshold: style/failure-threshold: info/' "seuil relevé à info"
s 's/ignored: \[\]/ignored: [DL3008]/' "règle désactivée (forme en ligne)"
s 's/ignored: \[\]/ignored:\n  - DL3008/' "règle désactivée (forme liste)"
s 's/  - cgr.dev/  - cgr.dev\n  - docker.io/' "registre supplémentaire"
s 's/^override:/override:\n  warning:\n    - DL3008/' "override hors error"
a "ignored: []" "clé dupliquée"
a "  error:" "sous-clé override dupliquée"
rm -rf "$d"
echo
echo "# limites de Hadolint et contrôle qui les couvre"
w=$(mktemp -d)
lim() {
  printf "$2" > "$w/$1"
  echo "## $1"; sed 's/^/    /' "$w/$1"
  hadolint --no-color --config .hadolint.yaml "$w/$1" | sed "s#$w/##"; echo "hadolint exit: ${PIPESTATUS[0]}"
}
pin() {
  docker compose config --no-interpolate --format json \
    | "$PY" scripts/ci/check_pinning.py --compose-json - --dockerfile "$w/$1" \
    | sed "s#$w/##"
  echo "check_pinning exit: ${PIPESTATUS[1]}"
}
lim tag-mouvant 'FROM cgr.dev/chainguard/python:latest-dev\nUSER 65532\n'; pin tag-mouvant
lim tag-version 'FROM cgr.dev/chainguard/python:3.14\nUSER 65532\n'; pin tag-version
lim add-url "$B\nADD https://example.com/app.tar.gz /app/\nUSER 65532\n"; pin add-url
lim sans-user "$B\nRUN [\"true\"]\n"
echo "# -> USER : vérifié par inspection de l'image (65532:65532, evidence/after/image.txt)"
lim hors-registre 'FROM python:3.10-slim\nUSER 65532\n'
echo
echo "# dépendances Python : DL3013 accepte une contrainte, check_pinning.py exige =="
printf 'Flask>=3\n' > "$w/requirements.txt"; echo "## requirements.txt"; sed 's/^/    /' "$w/requirements.txt"
docker compose config --no-interpolate --format json \
  | "$PY" scripts/ci/check_pinning.py --compose-json - --requirements "$w/requirements.txt" \
  | sed "s#$w/##"
echo "check_pinning exit: ${PIPESTATUS[1]}"
rm -rf "$w"
echo
echo "# lecture du Dockerfile par check_pinning.py comparée à BuildKit (FROM scratch, sans téléchargement)"
echo "# BuildKit échoue sur « absent » quand ADD est une instruction réelle ; check_pinning.py doit refuser exactement ces ADD"
w=$(mktemp -d)
cmp() {
  printf "$2" > "$w/Dockerfile"
  echo "## $1"; sed 's/^/    /' "$w/Dockerfile" | cat -t
  docker buildx build --no-cache --progress=plain ${3:-} -o type=cacheonly "$w" > "$w/log" 2>&1
  grep -E '^#[0-9]+ \[[0-9]' "$w/log" | sed 's/^#[0-9]* /buildkit: /'
  grep -oE 'unterminated heredoc|"/absent[0-9]*": not found' "$w/log" | sort -u | sed 's/^/buildkit: erreur /'
  [ -n "${3:-}" ] && sed -n '/TARGET/,$p' "$w/log" | sed 's/^/buildkit: /'
  "$PY" -c 'import runpy,sys; p=runpy.run_path("scripts/ci/check_pinning.py"); print("check_pinning:", [e.split(": ",1)[1] for e in p["check_dockerfile"](sys.argv[1])])' "$w/Dockerfile"
}
cmp commentaire-antislash 'FROM scratch\n# commentaire \\\nADD absent /x\n'
cmp tabulation 'FROM scratch\nADD\tabsent /x\n'
cmp heredoc 'FROM scratch\nCOPY <<EOF /x\nADD absent /y\nEOF\n'
cmp faux-heredoc-guillemets "FROM scratch AS u\nRUN echo '<<EOF'\nFROM scratch\nADD absent /x\n"
cmp faux-heredoc-json 'FROM scratch AS u\nRUN ["echo", "<<EOF"]\nFROM scratch\nADD absent /x\n'
cmp faux-heredoc-colle 'FROM scratch AS u\nRUN echo a<<EOF\nFROM scratch\nADD absent /x\n'
cmp delimiteur-complet 'FROM scratch\nCOPY <<EOF-X /x\ntexte\nEOF-X\n\nADD absent /y\n'
cmp delimiteur-numerique 'FROM scratch\nCOPY <<123 /x\nADD texte /y\n123\n\n'
cmp delimiteur-entre-guillemets "FROM scratch\nCOPY <<'EOF-X' /x\nADD texte /y\nEOF-X\nADD absent /z\n"
cmp descripteur 'FROM scratch AS u\nRUN cat 0<<EOF\nADD absent /y\nEOF\nFROM scratch\nADD absent2 /z\n'
cmp non-termine 'FROM scratch\nCOPY <<EOF /x\nADD absent /y\n'
cmp mot-cle-coupe 'FROM scratch\nA\\\nDD absent /x\n'
cmp heredoc-nom-vide "FROM scratch\nCOPY <<'' /x\nADD absent /y\n\n"
echo "# syntaxes ambiguës : check_pinning.py refuse au lieu d'interpréter"
cmp double-antislash 'FROM scratch\nLABEL p=C:\\\\\nADD absent /x\n'
cmp directive-escape '# escape=`\nFROM scratch\nLABEL n=v`\nADD absent /x\n'
cmp directive-indentee '  # escape=`\nFROM scratch\nLABEL n=v`\nADD absent /x\n'
cmp directive-apres-inconnue '# anything=x\n# escape=`\nFROM scratch\nLABEL n=v`\nADD absent /x\n'
cmp bom '\xef\xbb\xbfFROM cgr.dev/chainguard/python:latest-dev AS mutable\n' --call=targets
rm -rf "$w"
