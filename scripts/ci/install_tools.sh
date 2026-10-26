#!/usr/bin/env bash
# Outils Linux amd64 vérifiés avant installation ; scans des deux architectures ici.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
install_archive() {
  local url=$1 checksum=$2 binary=$3
  curl --retry 3 -fsSL "$url" -o "$work/archive.tgz"
  printf '%s  %s\n' "$checksum" "$work/archive.tgz" | sha256sum --check --strict
  tar -xzf "$work/archive.tgz" -C "$work" "$binary"
  sudo install -m 0755 "$work/$binary" "/usr/local/bin/$binary"
}
for tool in "$@"; do
  case "$tool" in
    dive) install_archive https://github.com/wagoodman/dive/releases/download/v0.13.1/dive_0.13.1_linux_amd64.tar.gz 0970549eb4a306f8825a84145a2534153badb4d7dcf3febd1967c706367c3d0e dive ;;
    trivy) install_archive https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f trivy ;;
    crane) install_archive https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz 0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0 crane ;;
    *) echo 'Outil inconnu' >&2; exit 1 ;;
  esac
done
