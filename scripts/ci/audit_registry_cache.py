#!/usr/bin/env python3
"""Audit d'un cache registre : blobs téléchargés par digest, puis secret."""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

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
        raise RuntimeError(f"HTTP {error.code}") from None


def manifest_digests(manifest):
    if not isinstance(manifest.get("config"), dict) or not manifest.get("layers"):
        raise ValueError("cache OCI sans config ou couches")
    descriptors = [manifest["config"], *manifest["layers"]]
    digests = set()
    for descriptor in descriptors:
        digest = descriptor.get("digest", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("digest SHA256 de cache invalide")
        digests.add(digest)
    return digests


def validate_digest(data, digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("digest SHA256 de cache invalide")
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("digest de cache divergent")


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
    if reference.startswith("sha256:"):
        validate_digest(manifest_bytes, reference)
    if secret_contains(manifest_bytes, secret):
        raise RuntimeError("jeton trouvé dans le manifeste du cache registre")
    digests = manifest_digests(manifest)
    leaked = []
    for digest in sorted(digests):
        blob = fetch_blob(registry, repository, digest, token)
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            raise ValueError("cache zstd non auditable ; exporter en gzip")
        if secret_contains(blob, secret):
            leaked.append(digest)
    if leaked:
        raise RuntimeError("jeton trouvé dans les blobs du cache registre")
    return {
        "registry": registry,
        "repository": repository,
        "reference": reference,
        "manifest": manifest,
        "blobs": sorted(digests),
        "blob_count": len(digests),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    token = Path(args.secret_file).read_bytes().strip()
    if not token:
        raise SystemExit("jeton de contrôle vide")
    try:
        result = audit(args.ref, token)
    except Exception as error:
        # Seuls les diagnostics contrôlés sont publiés, jamais les réponses réseau.
        safe_messages = {
            "référence de cache invalide", "référence de cache sans tag ni digest",
            "jeton d'accès registre introuvable", "cache OCI sans config ou couches",
            "digest SHA256 de cache invalide", "digest de cache divergent",
            "cache zstd non auditable ; exporter en gzip",
            "jeton trouvé dans le manifeste du cache registre",
            "jeton trouvé dans les blobs du cache registre",
        }
        message = str(error)
        if isinstance(error, urllib.error.HTTPError):
            detail = f"HTTP {error.code}"
        elif message in safe_messages or re.fullmatch(r"HTTP [1-5][0-9]{2}", message):
            detail = message
        else:
            detail = "cause non publiée"
        raise SystemExit(
            f"audit du cache registre échoué ({type(error).__name__}) : {detail}"
        ) from None
    print(f"Cache registre audité: {result['blob_count']} blobs, sans jeton.")


if __name__ == "__main__":
    main()
