#!/usr/bin/env bash
# Porte d'admission : lectures publiques uniquement, sans identifiant ni artefact.
# Les empreintes SBOM attendues viennent des outputs du job release (même run).
set -euo pipefail
: "${REPOSITORY:?}" "${VERSION:?}" "${MINOR:?}" "${MAJOR:?}"
: "${INDEX_DIGEST:?}" "${AMD64_DIGEST:?}" "${ARM64_DIGEST:?}"
: "${AMD64_SBOM_COMPONENTS:?}" "${AMD64_SBOM_SHA256:?}"
: "${ARM64_SBOM_COMPONENTS:?}" "${ARM64_SBOM_SHA256:?}"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_REF:?}" "${GITHUB_SHA:?}"
ci=$(dirname "${BASH_SOURCE[0]}")
for digest in "$INDEX_DIGEST" "$AMD64_DIGEST" "$ARM64_DIGEST"; do
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "digest invalide ou absent : « $digest »" >&2; exit 1; }
done
for hash in "$AMD64_SBOM_SHA256" "$ARM64_SBOM_SHA256"; do
  [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo 'empreinte SBOM attendue invalide' >&2; exit 1; }
done
for count in "$AMD64_SBOM_COMPONENTS" "$ARM64_SBOM_COMPONENTS"; do
  [[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo 'nombre de composants attendu invalide' >&2; exit 1; }
done
[[ "$GITHUB_REF" =~ ^refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] \
  || { echo 'admission réservée aux tags vX.Y.Z' >&2; exit 1; }

# Signé par ce workflow, pour ce tag, via l'OIDC de GitHub Actions.
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/ci.yaml@$GITHUB_REF"
issuer=https://token.actions.githubusercontent.com
trust=(--certificate-identity "$identity" --certificate-oidc-issuer "$issuer"
  --certificate-github-workflow-sha "$GITHUB_SHA")
# Variante locale de test (clé jetable) ; interdite sur un runner GitHub.
if [ -n "${COSIGN_VERIFY_TEST_ARGS:-}" ]; then
  [ "${GITHUB_ACTIONS:-}" != true ] || { echo 'COSIGN_VERIFY_TEST_ARGS interdit en CI' >&2; exit 1; }
  read -r -a trust <<< "$COSIGN_VERIFY_TEST_ARGS"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export DOCKER_CONFIG="$work/docker"   # lecture anonyme : aucun identifiant du runner

# Les tags publiés pointent vers l'index signé, qui contient les deux manifestes attestés.
for tag in "$VERSION" "$MINOR" "$MAJOR"; do
  [ "$(crane digest "$REPOSITORY:$tag")" = "$INDEX_DIGEST" ] \
    || { echo "$REPOSITORY:$tag ne pointe pas vers $INDEX_DIGEST" >&2; exit 1; }
done
crane manifest "$REPOSITORY@$INDEX_DIGEST" > "$work/index.json"
python3 "$ci/check_index.py" "$work/index.json" "$AMD64_DIGEST" "$ARM64_DIGEST"

for digest in "$INDEX_DIGEST" "$AMD64_DIGEST" "$ARM64_DIGEST"; do
  cosign verify "${trust[@]}" "$REPOSITORY@$digest" > "$work/verify.json"
done
for arch in amd64 arm64; do
  case "$arch" in
    amd64) digest=$AMD64_DIGEST components=$AMD64_SBOM_COMPONENTS hash=$AMD64_SBOM_SHA256 ;;
    arm64) digest=$ARM64_DIGEST components=$ARM64_SBOM_COMPONENTS hash=$ARM64_SBOM_SHA256 ;;
  esac
  cosign verify-attestation --type cyclonedx "${trust[@]}" "$REPOSITORY@$digest" > "$work/attestation-$arch.json"
  python3 "$ci/sbom_identity.py" attestation --verify-output "$work/attestation-$arch.json" \
    --digest "$digest" --components "$components" --sha256 "$hash"
done
echo "Admission réussie : $INDEX_DIGEST signé par $identity, SBOM attestées"
