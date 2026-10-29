#!/usr/bin/env python3
"""Contrôles d'identité de la SBOM CycloneDX, avant attestation puis à l'admission.

- ``artifact`` : l'artefact téléchargé est bien celui du job producteur
  (ID, nom, run, commit, non expiré), d'après la réponse de l'API GitHub ;
- ``verify`` : la SBOM décrit bien l'image de cette architecture ;
- ``attestation`` : le prédicat attesté dans le registre est la SBOM validée.
"""

import argparse
import base64
import hashlib
import json
import re
import sys

CYCLONEDX_PREDICATE_TYPE = 'https://cyclonedx.org/bom'
ARTIFACT_NAME = re.compile(r'sbom-(amd64|arm64)-([1-9][0-9]*)')
LAYER_PROPERTY = re.compile(r'syft:location:[0-9]+:layerID')
SHA256 = re.compile(r'sha256:[0-9a-f]{64}')


def canonical_sha256(document):
    """Empreinte du JSON canonique : indépendante de la mise en forme."""
    data = json.dumps(document, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()
    return hashlib.sha256(data).hexdigest()


def check_artifact(meta, expected):
    """Valide la réponse de ``GET /repos/{repo}/actions/artifacts/{id}``."""
    if str(meta.get('id')) != expected['artifact_id']:
        raise ValueError('ID d’artefact inattendu')
    found = ARTIFACT_NAME.fullmatch(str(meta.get('name')))
    if not found or found.group(1) != expected['arch']:
        raise ValueError('nom d’artefact SBOM inattendu ou d’une autre architecture')
    # La SBOM est produite par le job de scan : sa tentative ne dépasse jamais
    # celle du run courant (un « Re-run failed jobs » ne relance pas les scans verts).
    if not 1 <= int(found.group(2)) <= int(expected['run_attempt']):
        raise ValueError('tentative de l’artefact incohérente avec le run')
    if meta.get('expired') is not False:
        raise ValueError('artefact expiré')
    run = meta.get('workflow_run') or {}
    if str(run.get('id')) != expected['run_id']:
        raise ValueError('artefact produit par un autre run')
    if run.get('head_sha') != expected['commit']:
        raise ValueError('artefact produit pour un autre commit')


def layer_ids(components):
    """DiffIDs des couches citées par Syft (``syft:location:N:layerID``)."""
    found = set()
    for component in components:
        for prop in component.get('properties') or []:
            if LAYER_PROPERTY.fullmatch(prop.get('name', '')):
                found.add(prop.get('value'))
        found |= layer_ids(component.get('components') or [])
    return found


def check_sbom(sbom, image, arch):
    """Vérifie que la SBOM décrit l'image vérifiée de cette architecture.

    La version du composant doit être le config digest de l'archive vérifiée.
    Le producteur Syft fournit ``--source-version <image-id>`` ; les DiffIDs
    constituent un contrôle supplémentaire, jamais une identité suffisante.
    """
    if image['platform'] != 'linux/' + arch:
        raise ValueError('archive d’une autre plateforme que celle attendue')
    if sbom.get('bomFormat') != 'CycloneDX' or not sbom.get('specVersion'):
        raise ValueError('document non CycloneDX')
    component = (sbom.get('metadata') or {}).get('component') or {}
    if component.get('type') != 'container':
        raise ValueError('metadata.component n’est pas une image (container)')
    components = sbom.get('components')
    if not isinstance(components, list) or not components:
        raise ValueError('SBOM sans composants')
    layers = layer_ids(components)
    if not layers:
        raise ValueError('aucune couche citée : identité de l’image invérifiable')
    unknown = layers - set(image['diff_ids'])
    if unknown:
        raise ValueError(
            f'{len(unknown)} couche(s) de la SBOM absentes de l’image {arch} '
            '(SBOM d’une autre image ou architecture)')
    version = component.get('version')
    if not SHA256.fullmatch(str(version)):
        raise ValueError('metadata.component.version n’est pas un digest sha256')
    if version != image['image_id']:
        raise ValueError('metadata.component.version ≠ config digest de l’image')
    return {
        'components': len(components),
        'sha256': canonical_sha256(sbom),
        'identity': 'config-digest',
    }


def check_attestations(output, digest, components, sha256):
    """Valide la sortie de ``cosign verify-attestation`` (une ligne JSON par DSSE).

    Cosign a déjà vérifié signature et identité ; on contrôle ici ce qu'elle
    atteste : le sujet est le manifeste attendu, le prédicat est la SBOM validée.
    """
    if not SHA256.fullmatch(digest):
        raise ValueError('digest attendu invalide')
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        raise ValueError('aucune attestation CycloneDX vérifiée')
    for line in lines:
        statement = json.loads(base64.b64decode(json.loads(line)['payload']))
        if statement.get('predicateType') != CYCLONEDX_PREDICATE_TYPE:
            raise ValueError('type de prédicat inattendu')
        subjects = [s.get('digest', {}).get('sha256')
                    for s in statement.get('subject') or []]
        if subjects != [digest.removeprefix('sha256:')]:
            raise ValueError('sujet de l’attestation ≠ manifeste attendu')
        predicate = statement.get('predicate') or {}
        if len(predicate.get('components') or []) != int(components):
            raise ValueError('nombre de composants attesté inattendu')
        if canonical_sha256(predicate) != sha256:
            raise ValueError('prédicat attesté ≠ SBOM validée en CI')
    return len(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    art = sub.add_parser('artifact')
    art.add_argument('--metadata', required=True)
    art.add_argument('--artifact-id', required=True)
    art.add_argument('--arch', required=True, choices=['amd64', 'arm64'])
    art.add_argument('--run-id', required=True)
    art.add_argument('--commit', required=True)
    art.add_argument('--run-attempt', required=True)
    ver = sub.add_parser('verify')
    ver.add_argument('--sbom', required=True)
    ver.add_argument('--image-json', required=True)
    ver.add_argument('--arch', required=True, choices=['amd64', 'arm64'])
    ver.add_argument('--github-output')
    att = sub.add_parser('attestation')
    att.add_argument('--verify-output', required=True)
    att.add_argument('--digest', required=True)
    att.add_argument('--components', required=True)
    att.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'artifact':
            with open(args.metadata) as stream:
                check_artifact(json.load(stream), {
                    'artifact_id': args.artifact_id, 'arch': args.arch,
                    'run_id': args.run_id, 'commit': args.commit,
                    'run_attempt': args.run_attempt})
            result = {'artifact': 'ok'}
        elif args.command == 'verify':
            with open(args.sbom) as stream, open(args.image_json) as image:
                result = check_sbom(json.load(stream), json.load(image),
                                    args.arch)
            if args.github_output:
                with open(args.github_output, 'a') as out:
                    out.write(f'components={result["components"]}\n'
                              f'sha256={result["sha256"]}\n')
        else:
            with open(args.verify_output) as stream:
                result = {'attestations': check_attestations(
                    stream.read(), args.digest, args.components, args.sha256)}
    except (ValueError, KeyError, TypeError) as error:
        sys.exit(f'sbom_identity : {type(error).__name__} : {error}')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
