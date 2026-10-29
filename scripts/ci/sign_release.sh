#!/usr/bin/env bash
# Signe l'index publié (récursivement) et atteste la SBOM de chaque plateforme.
# Appelé depuis ci.yaml (job release) pour que l'identité Fulcio soit ci.yaml.
# Tout est adressé par digest : un tag est mutable, jamais signé.
set -euo pipefail
: "${REPOSITORY:?}" "${INDEX_DIGEST:?}" "${AMD64_DIGEST:?}" "${ARM64_DIGEST:?}"
sbom_amd64=${SBOM_AMD64:-dist/sbom/amd64/sbom.cdx.json}
sbom_arm64=${SBOM_ARM64:-dist/sbom/arm64/sbom.cdx.json}
ci=$(dirname "${BASH_SOURCE[0]}")
# Chaque entrée est contrôlée AVANT le premier appel à Cosign.
[[ "$REPOSITORY" =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]] \
  || { echo 'dépôt invalide (tag ou digest interdit)' >&2; exit 1; }
for digest in "$INDEX_DIGEST" "$AMD64_DIGEST" "$ARM64_DIGEST"; do
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo "digest invalide ou absent : « $digest »" >&2; exit 1; }
done
[ "$(printf '%s\n' "$INDEX_DIGEST" "$AMD64_DIGEST" "$ARM64_DIGEST" | sort -u | wc -l)" -eq 3 ] \
  || { echo 'digests index/amd64/arm64 non distincts' >&2; exit 1; }
for sbom in "$sbom_amd64" "$sbom_arm64"; do
  [ -f "$sbom" ] || { echo "SBOM absente : $sbom" >&2; exit 1; }
done
# Variante locale de test (clé jetable) ; interdite sur un runner GitHub.
extra=()
if [ -n "${COSIGN_SIGN_TEST_ARGS:-}" ]; then
  [ "${GITHUB_ACTIONS:-}" != true ] || { echo 'COSIGN_SIGN_TEST_ARGS interdit en CI' >&2; exit 1; }
  read -r -a extra <<< "$COSIGN_SIGN_TEST_ARGS"
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# L'index à signer contient exactement les deux manifestes à attester.
crane manifest "$REPOSITORY@$INDEX_DIGEST" > "$work/index.json"
python3 "$ci/check_index.py" "$work/index.json" "$AMD64_DIGEST" "$ARM64_DIGEST"

cosign sign --yes --recursive ${extra[@]+"${extra[@]}"} "$REPOSITORY@$INDEX_DIGEST"
cosign attest --yes --type cyclonedx --predicate "$sbom_amd64" ${extra[@]+"${extra[@]}"} "$REPOSITORY@$AMD64_DIGEST"
cosign attest --yes --type cyclonedx --predicate "$sbom_arm64" ${extra[@]+"${extra[@]}"} "$REPOSITORY@$ARM64_DIGEST"
echo "Index $INDEX_DIGEST signé ; SBOM attestée pour $AMD64_DIGEST et $ARM64_DIGEST"
