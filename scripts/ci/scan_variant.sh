#!/usr/bin/env bash
set -euo pipefail
: "${IMAGE:?}" "${EXPECTED_PLATFORM:?}"
scripts/ci/load_verified_image.sh dist
mkdir -p reports
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dive --ci --ci-config .dive-ci --source docker-archive dist/image.tar > reports/dive.txt 2>&1
# Tester le scanner avec une fuite isolée ; aucun rapport de secret n’est publié.
printf 'TP2_%048d' 0 > "$work/leak.txt"
rc=0
trivy fs --scanners secret --secret-config scripts/ci/trivy-secret.yaml \
  --format json --output "$work/leak.json" --exit-code 1 "$work" > /dev/null 2>&1 || rc=$?
[ "$rc" = 1 ]
python3 - "$work/leak.json" <<'PY'
import json, sys
findings = json.load(open(sys.argv[1]))
assert any(s['RuleID'] == 'tp2-build-token' for r in findings['Results']
           for s in r.get('Secrets', []))
PY
for archive in dist/image.tar dist/builder.tar; do
  trivy image --input "$archive" --scanners secret \
    --secret-config scripts/ci/trivy-secret.yaml --exit-code 1 \
    --format json --output "$work/secrets.json" > /dev/null 2>&1
done
trivy image --input dist/image.tar --scanners vuln --format json --output reports/trivy-image-full.json
trivy image --input dist/image.tar --scanners vuln --skip-db-update --format table --output reports/trivy-image-full.txt
trivy image --input dist/image.tar --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
trivy fs --scanners vuln --skip-db-update --skip-dirs dist,reports --format json --output reports/trivy-deps-full.json .
trivy fs --scanners vuln --skip-db-update --skip-dirs dist,reports --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
db_image=$(docker compose config --no-interpolate --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["db"]["image"])')
trivy image --image-src remote --platform "$EXPECTED_PLATFORM" --scanners vuln --skip-db-update --format json --output reports/trivy-db-full.json "$db_image"
trivy image --image-src remote --platform "$EXPECTED_PLATFORM" --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$db_image"
