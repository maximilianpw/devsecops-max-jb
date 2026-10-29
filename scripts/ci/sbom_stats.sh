#!/usr/bin/env bash
# Statistiques d'un SBOM CycloneDX + SPDX ; échoue sur un inventaire vide.
set -euo pipefail
cdx=${1:?usage: sbom_stats.sh <sbom.cdx.json> <sbom.spdx.json>}
spdx=${2:?usage: sbom_stats.sh <sbom.cdx.json> <sbom.spdx.json>}
components=$(jq -e '.components | length | select(. > 0)' "$cdx")
packages=$(jq -e '.packages | length | select(. > 0)' "$spdx")
echo "CycloneDX composants : $components"
jq -r '.components | group_by(.type)[] | "  \(.[0].type) : \(length)"' "$cdx"
echo "SPDX paquets : $packages"
echo '--- Licences (CycloneDX)'
jq -r '[.components[].licenses[]? | .license.id // .license.name // .expression] | unique[]' "$cdx"
echo '--- Licences (SPDX)'
jq -r '[.packages[] | .licenseConcluded, .licenseDeclared] | map(select(. != null and . != "NOASSERTION")) | unique[]' "$spdx"
echo '--- PURL (CycloneDX)'
jq -r '.components[].purl // empty' "$cdx" | sort -u
