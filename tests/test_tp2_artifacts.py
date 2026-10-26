"""Les artefacts téléchargés ne peuvent pas redéfinir leur identité attendue."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / 'scripts' / 'ci' / f'{name}.py'
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


images = load('image_archive')
secrets = load('audit_secret')
indexes = load('check_index')


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


@pytest.fixture
def artifact(tmp_path):
    layer = tar_bytes({'app': b'hello'})
    config = json.dumps({
        'os': 'linux', 'architecture': 'arm64',
        'rootfs': {'type': 'layers', 'diff_ids': [images.digest(layer)]},
    }).encode()
    manifest = [{'Config': 'config.json', 'Layers': ['layer.tar']}]
    archive = tar_bytes({
        'manifest.json': json.dumps(manifest).encode(),
        'config.json': config, 'layer.tar': layer,
    })
    expected = {
        'image_id': images.digest(config), 'platform': 'linux/arm64',
        'archive_sha256': hashlib.sha256(archive).hexdigest(),
        'commit': 'a' * 40, 'run_id': '123', 'run_attempt': '1',
    }
    (tmp_path / 'image.tar').write_bytes(archive)
    (tmp_path / 'metadata.json').write_text(json.dumps(expected))
    return tmp_path, expected


def test_verified_artifact(artifact):
    path, expected = artifact
    assert images.verify(path, expected)['image_id'] == expected['image_id']


@pytest.mark.parametrize('key,value', [
    ('archive_sha256', '0' * 64), ('image_id', 'sha256:' + '0' * 64),
    ('platform', 'linux/amd64'), ('commit', 'b' * 40),
    ('run_id', '124'), ('run_attempt', '2'),
])
def test_archive_cannot_redefine_trusted_metadata(artifact, key, value):
    path, expected = artifact
    metadata = dict(expected, **{key: value})
    (path / 'metadata.json').write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        images.verify(path, expected)


def test_wrong_architecture_even_when_metadata_claims_expected(artifact):
    path, expected = artifact
    expected['platform'] = 'linux/amd64'
    (path / 'metadata.json').write_text(json.dumps(expected))
    with pytest.raises(ValueError, match='platform'):
        images.verify(path, expected)


def test_missing_metadata(artifact):
    path, expected = artifact
    (path / 'metadata.json').unlink()
    with pytest.raises(FileNotFoundError):
        images.verify(path, expected)


def test_corrupt_archive(artifact):
    path, expected = artifact
    with (path / 'image.tar').open('ab') as stream:
        stream.write(b'corruption')
    with pytest.raises(ValueError, match='checksum'):
        images.verify(path, expected)


def test_modified_layer_cannot_use_old_config(artifact):
    path, _ = artifact
    with tarfile.open(path / 'image.tar') as archive:
        files = {m.name: archive.extractfile(m).read() for m in archive}
    files['layer.tar'] = tar_bytes({'app': b'changed'})
    (path / 'image.tar').write_bytes(tar_bytes(files))
    with pytest.raises(ValueError, match='DiffIDs'):
        images.describe(path / 'image.tar')


def test_deleted_secret_in_earlier_layer_still_detected():
    token = b'TP2_' + b'a' * 48
    early = tar_bytes({'token': token})
    later = tar_bytes({'.wh.token': b''})
    archive = tar_bytes({'early/layer.tar': early, 'later/layer.tar': later})
    assert secrets.contains(archive, token)
    assert not secrets.contains(archive, b'another-token')


def test_compressed_intermediate_layer_secret_detected():
    import gzip
    token = b'TP2_' + b'b' * 48
    assert secrets.contains(gzip.compress(tar_bytes({'token': token})), token)


def index(manifests):
    return {'manifests': [
        {'platform': {'os': 'linux', 'architecture': arch}, 'digest': digest}
        for arch, digest in manifests
    ]}


def test_exact_two_platform_index():
    indexes.check(index([('amd64', 'a'), ('arm64', 'b')]), {
        'linux/amd64': 'a', 'linux/arm64': 'b',
    })


@pytest.mark.parametrize('manifests', [
    [('amd64', 'a')], [('amd64', 'a'), ('amd64', 'a')],
    [('amd64', 'a'), ('arm64', 'wrong')],
    [('amd64', 'a'), ('arm64', 'b'), ('unknown', 'c')],
])
def test_incomplete_or_replaced_index_rejected(manifests):
    with pytest.raises(ValueError):
        indexes.check(index(manifests), {'linux/amd64': 'a', 'linux/arm64': 'b'})
