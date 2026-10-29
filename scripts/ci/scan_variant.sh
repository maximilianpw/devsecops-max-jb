#!/usr/bin/env bash
# Rapports complets d'abord, puis tous les gates : un gate rouge n'empêche ni
# les autres rapports ni les autres gates ; le script échoue à la fin.
set -euo pipefail
: "${IMAGE:?}" "${EXPECTED_PLATFORM:?}"
scripts/ci/load_verified_image.sh dist
mkdir -p reports
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=()
gate() {
  local name=$1; shift
  if ! "$@"; then failed+=("$name"); fi
}

# Tester le scanner avec une fuite isolée ; aucun rapport de secret n'est publié.
# Contrôle préalable : s'il échoue, les scans de secrets ne prouvent rien.
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
rm "$work/leak.txt" "$work/leak.json"

db_image=$(docker compose config --no-interpolate --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["services"]["db"]["image"])')

# Rapports complets (toutes sévérités) ; le premier met à jour la base Trivy.
# Une erreur d’outil est bloquante, sans masquer les autres rapports et gates.
gate report-image-json trivy image --input dist/image.tar --scanners vuln --format json --output reports/trivy-image-full.json
gate report-image-table trivy image --input dist/image.tar --scanners vuln --skip-db-update --format table --output reports/trivy-image-full.txt
gate report-deps trivy fs --scanners vuln --skip-db-update --skip-dirs dist,reports --format json --output reports/trivy-deps-full.json .
gate report-db trivy image --image-src remote --platform "$EXPECTED_PLATFORM" --scanners vuln --skip-db-update --format json --output reports/trivy-db-full.json "$db_image"
mkdir -p reports/sbom
gate sbom syft scan docker-archive:dist/image.tar -o cyclonedx-json=reports/sbom/sbom.cdx.json -o spdx-json=reports/sbom/sbom.spdx.json
# .grype.yaml est chargé implicitement : seuil levé pour ce rapport, VEX conservé.
gate report-grype env GRYPE_FAIL_ON_SEVERITY= grype sbom:reports/sbom/sbom.cdx.json --only-fixed=false -o json --file reports/grype-full.json
gate sbom-stats scripts/ci/sbom_stats.sh reports/sbom/sbom.cdx.json reports/sbom/sbom.spdx.json > reports/sbom-stats.txt

# Gates.
gate dive dive --ci --ci-config .dive-ci --source docker-archive dist/image.tar > reports/dive.txt 2>&1
for archive in image builder; do
  gate "secret-$archive" trivy image --input "dist/$archive.tar" --scanners secret \
    --secret-config scripts/ci/trivy-secret.yaml --exit-code 1 \
    --format json --output "$work/secrets.json"
done
gate trivy-image trivy image --input dist/image.tar --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
gate trivy-deps trivy fs --scanners vuln --skip-db-update --skip-dirs dist,reports --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .
gate trivy-db trivy image --image-src remote --platform "$EXPECTED_PLATFORM" --scanners vuln --skip-db-update --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$db_image"
gate grype-sbom grype sbom:reports/sbom/sbom.cdx.json --config .grype.yaml

if [ "${#failed[@]}" -ne 0 ]; then
  echo "Gates en échec : ${failed[*]}" >&2
  exit 1
fi
echo 'Tous les gates de scan sont réussis.'
