#!/usr/bin/env python3
"""Recherche un jeton factice dans les archives et logs, sans l’afficher."""

import argparse
import gzip
import io
from pathlib import Path
import tarfile


def contains(data, token):
    if token in data:
        return True
    if data.startswith(b'\x1f\x8b'):
        return contains(gzip.decompress(data), token)
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data))
    except tarfile.ReadError:
        return False
    with archive:
        for member in archive:
            if token in member.name.encode() or token in member.linkname.encode():
                return True
            if member.isfile() and contains(archive.extractfile(member).read(), token):
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('secret_file')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    token = Path(args.secret_file).read_bytes().strip()
    if not token:
        raise SystemExit('jeton de contrôle vide')
    for index, path in enumerate(args.paths):
        if contains(Path(path).read_bytes(), token):
            raise SystemExit(f'fuite détectée dans l’entrée {index + 1} (expurgée)')
    print('Absence du jeton vérifiée dans toutes les entrées et couches archivées.')


if __name__ == '__main__':
    main()
