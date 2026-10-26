#!/usr/bin/env python3
"""Inspecte une archive Docker sans extraction et vérifie chaque DiffID."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import tarfile


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def describe(path):
    with tarfile.open(path) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)):
            raise ValueError('entrées dupliquées dans l’archive')

        def read(name):
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError('entrée d’image non régulière')
            return archive.extractfile(member).read()

        manifests = json.loads(read('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('une seule image attendue')
        manifest = manifests[0]
        config_bytes = read(manifest['Config'])
        config = json.loads(config_bytes)
        diff_ids = []
        for layer in manifest['Layers']:
            data = read(layer)
            if data.startswith(b'\x1f\x8b'):
                data = gzip.decompress(data)
            diff_ids.append(digest(data))
        if diff_ids != config['rootfs']['diff_ids']:
            raise ValueError('couches différentes des DiffIDs de la configuration')
        return {
            'image_id': digest(config_bytes),
            'platform': config['os'] + '/' + config['architecture'],
            'diff_ids': diff_ids,
        }


def verify(directory, expected):
    path = Path(directory)
    checksum = hashlib.sha256()
    with (path / 'image.tar').open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    archive_sha = checksum.hexdigest()
    metadata = json.loads((path / 'metadata.json').read_text())
    actual = describe(path / 'image.tar')
    if archive_sha != expected['archive_sha256']:
        raise ValueError('checksum d’archive inattendu')
    for key in ['image_id', 'platform']:
        if actual[key] != expected[key]:
            raise ValueError(f'identité inattendue : {key}')
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ValueError(f'métadonnée absente ou permutée : {key}')
    return actual


def producer_attempt(expected, current):
    """Tentative du build : entier positif, jamais postérieure au run courant."""
    if not (expected.isdigit() and current.isdigit()):
        raise ValueError('tentative de run invalide')
    if not 1 <= int(expected) <= int(current):
        raise ValueError('tentative du producteur incohérente avec le run')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['describe', 'verify'])
    parser.add_argument('path')
    args = parser.parse_args()
    if args.command == 'describe':
        result = describe(args.path)
    else:
        expected = {
            'image_id': os.environ['EXPECTED_IMAGE_ID'],
            'archive_sha256': os.environ['EXPECTED_SHA256'],
            'platform': os.environ['EXPECTED_PLATFORM'],
            'commit': os.environ['GITHUB_SHA'],
            'run_id': os.environ['GITHUB_RUN_ID'],
            # Tentative du job producteur (output de confiance) : un « Re-run
            # failed jobs » relance le consommateur sans rebâtir l'artefact.
            'run_attempt': producer_attempt(
                os.environ['EXPECTED_RUN_ATTEMPT'],
                os.environ['GITHUB_RUN_ATTEMPT'],
            ),
        }
        result = verify(args.path, expected)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
