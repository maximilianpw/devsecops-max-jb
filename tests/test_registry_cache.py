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


def test_registry_cache_audit_rejects_empty_manifest(monkeypatch):
    monkeypatch.setattr(
        audit, 'fetch_manifest', lambda *args: ({'manifests': []}, b'{}'))
    with pytest.raises(ValueError, match='sans config'):
        audit.audit('ghcr.io/example/repo:buildcache-amd64', SECRET, 'token')


def test_registry_cache_rejects_unknown_digest_algorithm():
    with pytest.raises(ValueError, match='SHA256'):
        audit.validate_digest(b'clean', 'unknown:unverified')


def test_registry_cache_cli_reaches_audit(tmp_path, monkeypatch, capsys):
    secret = tmp_path / 'token'
    secret.write_bytes(SECRET)
    monkeypatch.setattr('sys.argv', [
        'audit_registry_cache.py', '--secret-file', str(secret),
        '--ref', 'ghcr.io/example/repo:buildcache-amd64'])
    monkeypatch.setattr(audit, 'audit', lambda ref, token: {'blob_count': 2})
    audit.main()
    assert '2 blobs' in capsys.readouterr().out


@pytest.mark.parametrize('compression', ['gzip', 'zstd'])
def test_registry_cache_handles_compressed_leak(monkeypatch, compression):
    import gzip
    manifest, blobs = make_clean()
    blob = gzip.compress(SECRET) if compression == 'gzip' else (
        b'\x28\xb5\x2f\xfd' + b'opaque compressed bytes')
    digest = 'sha256:' + hashlib.sha256(blob).hexdigest()
    manifest['layers'] = [{'digest': digest}]
    blobs[digest] = blob
    monkeypatch.setattr('urllib.request.urlopen', urlopen_factory(
        json.dumps(manifest).encode(), blobs))
    with pytest.raises((ValueError, RuntimeError)):
        audit.audit('ghcr.io/example/repo:buildcache-amd64', SECRET)


@pytest.mark.parametrize('error,expected', [
    (ValueError('cache zstd non auditable ; exporter en gzip'), 'cache zstd'),
    (ValueError('digest de cache divergent'), 'digest de cache divergent'),
    (RuntimeError('jeton trouvé dans les blobs du cache registre'), 'jeton trouvé'),
    (RuntimeError('HTTP 403'), 'HTTP 403'),
    (audit.urllib.error.HTTPError('https://ghcr.io', 403, SECRET.decode(),
                                  {}, None), 'HTTP 403'),
    (RuntimeError(SECRET.decode()), 'cause non publiée'),
])
def test_audit_failure_is_diagnostic_and_does_not_expose_secret(
        tmp_path, monkeypatch, error, expected):
    secret = tmp_path / 'token'
    secret.write_bytes(SECRET)
    monkeypatch.setattr('sys.argv', [
        'audit_registry_cache.py', '--secret-file', str(secret),
        '--ref', 'ghcr.io/example/repo:buildcache-amd64'])

    def fail(*args):
        raise error

    monkeypatch.setattr(audit, 'audit', fail)
    with pytest.raises(SystemExit) as result:
        audit.main()
    message = str(result.value)
    assert expected in message
    assert type(error).__name__ in message
    assert SECRET.decode() not in message


def test_reusable_build_separates_cache_permissions_and_guards():
    # Inspecte les deux jobs YAML sans ajouter une dépendance au runner de test.
    import re
    source = (ROOT / '.github/workflows/tp2-build.yaml').read_text()
    blocks = dict(re.findall(
        r'^  (trusted|readonly):\n(.*?)(?=^  [\w-]+:|\Z)',
        source.split('jobs:\n', 1)[1], re.MULTILINE | re.DOTALL))
    trusted, readonly = blocks['trusted'], blocks['readonly']
    guard = ("inputs.cache-write && github.event_name == 'push' && "
             "(github.ref == 'refs/heads/main' || "
             "startsWith(github.ref, 'refs/tags/'))")
    assert f'if: ${{{{ {guard} }}}}' in trusted
    assert f'if: ${{{{ !({guard}) }}}}' in readonly
    assert '      packages: write\n' in trusted
    assert 'packages:' not in readonly
    assert 'GITHUB_TOKEN:' not in readonly
    assert "          CACHE_WRITE: 'false'\n" in readonly
    assert '          GITHUB_TOKEN:' in trusted
