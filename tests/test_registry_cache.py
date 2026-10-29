"""Audit d'un cache registre simulé, sans réseau réel."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / "scripts" / "ci"

spec = importlib.util.spec_from_file_location(
    "audit_registry_cache", CI / "audit_registry_cache.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

SECRET = b"TP2_" + b"r" * 48


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def make_clean():
    blob = b"clean cache layer"
    config = b"{}"
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    blob_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": config_digest},
        "layers": [{"digest": blob_digest}],
    }
    return manifest, {config_digest: config, blob_digest: blob}


def urlopen_factory(manifest_bytes, blobs):
    def fake_urlopen(request):
        url = request.full_url
        if "/token?" in url:
            return FakeResponse(b'{"token": "anonymous"}')
        if url.endswith("/manifests/buildcache-amd64"):
            return FakeResponse(manifest_bytes)
        for digest, data in blobs.items():
            if url.endswith("/blobs/" + digest):
                return FakeResponse(data)
        raise AssertionError(url)

    return fake_urlopen


def test_registry_cache_audit_accepts_clean_cache(monkeypatch):
    manifest, blobs = make_clean()
    manifest_bytes = json.dumps(manifest).encode()
    patch = urlopen_factory(manifest_bytes, blobs)
    monkeypatch.setattr("urllib.request.urlopen", patch)
    result = audit.audit("ghcr.io/example/repo:buildcache-amd64", SECRET)
    assert result["blob_count"] == 2


def test_registry_cache_audit_rejects_leak(monkeypatch):
    blob = SECRET
    config = b"{}"
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    blob_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    manifest = {
        "config": {"digest": config_digest},
        "layers": [{"digest": blob_digest}],
    }
    manifest_bytes = json.dumps(manifest).encode()
    blobs = {config_digest: config, blob_digest: blob}
    patch = urlopen_factory(manifest_bytes, blobs)
    monkeypatch.setattr("urllib.request.urlopen", patch)
    with pytest.raises(RuntimeError):
        audit.audit("ghcr.io/example/repo:buildcache-amd64", SECRET)


def test_registry_cache_audit_rejects_bad_digest(monkeypatch):
    blob = b"clean"
    config = b"{}"
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    blob_digest = "sha256:" + "0" * 64
    manifest = {
        "config": {"digest": config_digest},
        "layers": [{"digest": blob_digest}],
    }
    manifest_bytes = json.dumps(manifest).encode()
    blobs = {config_digest: config, blob_digest: blob}
    patch = urlopen_factory(manifest_bytes, blobs)
    monkeypatch.setattr("urllib.request.urlopen", patch)
    with pytest.raises(ValueError):
        audit.audit("ghcr.io/example/repo:buildcache-amd64", SECRET)
