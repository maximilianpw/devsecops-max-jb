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


def publish(token, paths, destination):
    """Copie les seuls fichiers sans jeton ; une fuite laisse un marqueur."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    leaked = []
    for index, path in enumerate(paths):
        path = Path(path)
        target = destination / path.name
        data = path.read_bytes()
        if contains(data, token):
            leaked.append(index + 1)
            target.unlink(missing_ok=True)
            Path(f'{target}.withheld').write_text(
                'Retenu : ce fichier contenait le jeton factice.\n')
        else:
            target.write_bytes(data)
    return leaked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish-to', metavar='DOSSIER',
                        help='copier dans DOSSIER les seuls fichiers sans jeton')
    parser.add_argument('secret_file')
    parser.add_argument('paths', nargs='+')
    args = parser.parse_args()
    token = Path(args.secret_file).read_bytes().strip()
    if not token:
        raise SystemExit('jeton de contrôle vide')
    if args.publish_to:
        leaked = publish(token, args.paths, args.publish_to)
        if leaked:
            raise SystemExit(f'fuite détectée, entrées retenues : {leaked}')
        print('Logs audités publiés sans jeton.')
        return
    for index, path in enumerate(args.paths):
        if contains(Path(path).read_bytes(), token):
            raise SystemExit(f'fuite détectée dans l’entrée {index + 1} (expurgée)')
    print('Absence du jeton vérifiée dans toutes les entrées et couches archivées.')


if __name__ == '__main__':
    main()
