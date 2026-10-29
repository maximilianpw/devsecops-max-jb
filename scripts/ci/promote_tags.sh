#!/usr/bin/env bash
# Appelé seulement après l'admission de l'index signé : tags posés sur son digest.
set -euo pipefail
: "${REPOSITORY:?}" "${VERSION:?}" "${MINOR:?}" "${MAJOR:?}" "${INDEX_DIGEST:?}"
[[ "$INDEX_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "digest invalide : « $INDEX_DIGEST »" >&2; exit 1; }
# Les trois tags sont posés l'un après l'autre : un échec peut laisser un état
# partiel. Le rapporter (lecture seule) pour la reprise documentée au README § 8.
report() {
  rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ]; then
    echo "Promotion interrompue ; index signé : $INDEX_DIGEST" >&2
    for tag in "$VERSION" "$MINOR" "$MAJOR"; do
      echo "  $REPOSITORY:$tag -> $(crane digest "$REPOSITORY:$tag" 2>/dev/null || echo 'absent ou illisible')" >&2
    done
  fi
  exit "$rc"
}
trap report EXIT
for tag in "$VERSION" "$MINOR" "$MAJOR"; do
  crane tag "$REPOSITORY@$INDEX_DIGEST" "$tag"
  test "$(crane digest "$REPOSITORY:$tag")" = "$INDEX_DIGEST"
done
echo "Tags $VERSION, $MINOR, $MAJOR posés sur l'index signé : $INDEX_DIGEST"
