#!/usr/bin/env python3
"""Audit d'un cache registre : blobs téléchargés par digest, puis secret."""

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import zstandard
except ImportError:  # pragma: no cover - dépendance optionnelle
    zstandard = None

from audit_secret import contains as secret_contains  # noqa: E402


def parse_ref(ref):
    ref = ref.strip()
    if "://" in ref:
        ref = ref.split("://", 1)[1]
    if "/" not in ref:
        raise ValueError("référence de cache invalide")
    registry, rest = ref.split("/", 1)
    if "@" in rest:
        repository, reference = rest.split("@", 1)
    elif ":" in rest:
        repository, reference = rest.rsplit(":", 1)
    else:
        raise ValueError("référence de cache sans tag ni digest")
    if not repository or not reference:
        raise ValueError("référence de cache invalide")
    return registry, repository, reference


def registry_token(registry, repository):
    if registry == "ghcr.io":
        url = (
            f"https://{registry}/token?scope=repository:{repository}:pull"
            f"&service={registry}"
        )
    else:
        url = f"https://{registry}/token?scope=repository:{repository}:pull"
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request) as response:
        payload = json.loads(response.read())
    token = payload.get("token") or payload.get("access_token")
    if not token:
        raise RuntimeError("jeton d'accès registre introuvable")
    return token


def http_get(url, token=None, headers=None):
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request) as response:
            response_headers = getattr(response, "headers", {})
            try:
                header_items = dict(response_headers.items())
            except AttributeError:
                header_items = dict(response_headers) if response_headers else {}
            return response.read(), header_items
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"HTTP {error.code} pour {url}: {error.reason}") from error


def manifest_digests(manifest):
    digests = set()
    if isinstance(manifest.get("config"), dict):
        digest = manifest["config"].get("digest")
        if digest:
            digests.add(digest)
    for layer in manifest.get("layers", []):
        if isinstance(layer, dict) and layer.get("digest"):
            digests.add(layer["digest"])
    for layer in manifest.get("fsLayers", []):
        if isinstance(layer, dict) and layer.get("blobSum"):
            digests.add(layer["blobSum"])
    if isinstance(manifest.get("layers"), list):
        pass
    return digests


def validate_digest(data, digest):
    algorithm, expected = digest.split(":", 1)
    if algorithm == "sha256":
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError(f"digest invalide: {digest}")
    elif algorithm == "sha512":
        actual = hashlib.sha512(data).hexdigest()
        if actual != expected:
            raise ValueError(f"digest invalide: {digest}")


def fetch_manifest(registry, repository, reference, token):
    url = f"https://{registry}/v2/{repository}/manifests/{reference}"
    headers = {
        "Accept": ", ".join([
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.index.v1+json",
        ])
    }
    data, _ = http_get(url, token=token, headers=headers)
    return json.loads(data), data


def fetch_blob(registry, repository, digest, token):
    url = f"https://{registry}/v2/{repository}/blobs/{digest}"
    data, _ = http_get(url, token=token)
    validate_digest(data, digest)
    return data


def audit(ref, secret, token=None):
    registry, repository, reference = parse_ref(ref)
    if token is None:
        token = registry_token(registry, repository)
    manifest, manifest_bytes = fetch_manifest(registry, repository, reference, token)
    if secret_contains(manifest_bytes, secret):
        raise RuntimeError("jeton trouvé dans le manifeste du cache registre")
    digests = manifest_digests(manifest)
    leaked = []
    for digest in sorted(digests):
        blob = fetch_blob(registry, repository, digest, token)
        if secret_contains(blob, secret):
            leaked.append(digest)
    if leaked:
        raise RuntimeError(f"jeton trouvé dans les blobs du cache registre: {leaked}")
    return {
        "registry": registry,
        "repository": repository,
        "reference": reference,
        "manifest": manifest,
        "blobs": sorted(digests),
        "blob_count": len(digests),
    }


def _resolve_args(args):
    secret_file = args.secret_file or args.secret_file_positional
    if not secret_file and args.secret_file_option:
        secret_file = args.secret_file_option
    ref = args.ref or args.ref_positional
    if not ref and args.ref_option:
        ref = args.ref_option
    if not secret_file:
        secret_file = os.environ.get("BUILD_SECRET_FILE")
    if not ref:
        ref = os.environ.get("REGISTRY_CACHE_REF") or os.environ.get("CACHE_REF")
    return secret_file, ref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("secret_file_positional", nargs="?", help="jeton")
    parser.add_argument("ref_positional", nargs="?", help="cache")
    parser.add_argument("--secret-file", dest="secret_file_option", help="jeton")
    parser.add_argument("--secret", dest="secret_file_option", help="jeton")
    parser.add_argument("--token-file", dest="secret_file_option", help="jeton")
    parser.add_argument("--ref", dest="ref_option", help="cache")
    parser.add_argument("--reference", dest="ref_option", help="cache")
    parser.add_argument("--cache-ref", dest="ref_option", help="cache")
    parser.add_argument("--registry-cache-ref", dest="ref_option", help="cache")
    args = parser.parse_args()

    secret_file, ref = _resolve_args(args)
    if not secret_file:
        raise SystemExit("fichier du jeton manquant")
    if not ref:
        raise SystemExit("référence du cache manquante")

    token = Path(secret_file).read_bytes().strip()
    if not token:
        raise SystemExit("jeton de contrôle vide")
    try:
        result = audit(ref, token)
    except Exception as error:  # noqa: BLE001 - CLI doit échouer proprement
        raise SystemExit(f"audit du cache registre échoué: {error}") from error
    print(
        "Cache registre audité: "
        f"{result['blob_count']} blob(s), aucun jeton détecté."
    )


# Alias pour les tests et les intégrations futures.
audit_registry_cache = audit
audit_cache = audit
check = audit
fetch_blobs = None


if __name__ == "__main__":
    main()
