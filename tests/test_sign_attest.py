"""Signature, attestation SBOM et admission : contrôles d'identité et câblage CI.

Les SBOM de ``tests/fixtures/sbom`` sont de vraies sorties de Syft. Le test de
bout en bout contre un registre local est ignoré sauf si ``TP2_TEST_REGISTRY``
désigne un registre joignable (voir ``test_local_registry_key_mode``).
"""

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'tests/fixtures/sbom'
WORKFLOW = (ROOT / '.github/workflows/ci.yaml').read_text()


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / 'scripts/ci' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sbom_identity = load('sbom_identity')


def fixture(arch):
    sbom = json.loads((FIXTURES / f'{arch}.cdx.json').read_text())
    image = json.loads((FIXTURES / f'{arch}.image.json').read_text())
    # Simule la convention --source-version sans altérer la fixture brute Syft.
    sbom['metadata']['component']['version'] = image['image_id']
    return sbom, image


def test_real_syft_sbom_matches_its_own_image():
    sbom, image = fixture('amd64')
    result = sbom_identity.check_sbom(sbom, image, 'amd64')
    assert result['components'] == len(sbom['components'])
    assert result['identity'] == 'config-digest'
    assert re.fullmatch(r'[0-9a-f]{64}', result['sha256'])


@pytest.mark.parametrize('sbom_arch,image_arch', [
    ('arm64', 'amd64'), ('amd64', 'arm64'),
])
def test_sbom_of_another_architecture_is_rejected(sbom_arch, image_arch):
    sbom, _ = fixture(sbom_arch)
    _, image = fixture(image_arch)
    with pytest.raises(ValueError, match='absentes de l’image'):
        sbom_identity.check_sbom(sbom, image, image_arch)


def test_platform_of_the_archive_must_match_the_expected_arch():
    sbom, image = fixture('amd64')
    with pytest.raises(ValueError, match='autre plateforme'):
        sbom_identity.check_sbom(sbom, image, 'arm64')


def test_syft_does_not_carry_the_config_digest():
    # Constat sur la sortie réelle de Syft 1.55.0 : metadata.component.version est
    # un digest de manifeste propre à Syft, pas le config digest de l'image.
    sbom, image = fixture('amd64')
    sbom = json.loads((FIXTURES / 'amd64.cdx.json').read_text())
    version = sbom['metadata']['component']['version']
    assert version != image['image_id']
    with pytest.raises(ValueError, match='config digest'):
        sbom_identity.check_sbom(sbom, image, 'amd64')
    sbom['metadata']['component']['version'] = image['image_id']
    result = sbom_identity.check_sbom(sbom, image, 'amd64')
    assert result['identity'] == 'config-digest'


@pytest.mark.parametrize('mutation,message', [
    (lambda s: s.update(bomFormat='SPDX'), 'CycloneDX'),
    (lambda s: s['metadata']['component'].update(type='library'), 'container'),
    (lambda s: s.update(components=[]), 'sans composants'),
    (lambda s: [c.pop('properties', None) for c in s['components']], 'aucune couche'),
    (lambda s: s['metadata']['component'].update(version='latest'), 'sha256'),
], ids=['format', 'type', 'empty', 'no-layer', 'version'])
def test_malformed_sbom_is_rejected(mutation, message):
    sbom, image = fixture('amd64')
    mutation(sbom)
    with pytest.raises(ValueError, match=message):
        sbom_identity.check_sbom(sbom, image, 'amd64')


def test_canonical_hash_ignores_formatting_but_not_content():
    sbom, _ = fixture('amd64')
    digest = sbom_identity.canonical_sha256
    reordered = json.loads(json.dumps(sbom, sort_keys=True, indent=4))
    assert digest(reordered) == digest(sbom)
    reordered['components'][0]['name'] = 'autre'
    assert digest(reordered) != digest(sbom)


EXPECTED = {'artifact_id': '4242', 'arch': 'amd64', 'run_id': '99',
            'commit': 'c' * 40, 'run_attempt': '2'}


def artifact_meta(**changes):
    meta = {'id': 4242, 'name': 'sbom-amd64-1', 'expired': False,
            'workflow_run': {'id': 99, 'head_sha': 'c' * 40}}
    meta.update(changes)
    return meta


def test_artifact_identity_accepts_a_scan_from_an_earlier_attempt():
    sbom_identity.check_artifact(artifact_meta(), EXPECTED)
    sbom_identity.check_artifact(artifact_meta(name='sbom-amd64-2'), EXPECTED)


@pytest.mark.parametrize('changes', [
    {'id': 4243},
    {'name': 'sbom-arm64-1'},
    {'name': 'sbom-amd64-3'},
    {'name': 'sbom-amd64-0'},
    {'name': 'images-amd64-1'},
    {'expired': True},
    {'expired': None},
    {'workflow_run': {'id': 98, 'head_sha': 'c' * 40}},
    {'workflow_run': {'id': 99, 'head_sha': 'd' * 40}},
    {'workflow_run': None},
], ids=lambda changes: next(iter(changes)) + '=' + str(list(changes.values())[0])[:20])
def test_artifact_identity_rejects(changes):
    with pytest.raises(ValueError):
        sbom_identity.check_artifact(artifact_meta(**changes), EXPECTED)


DIGEST = 'sha256:' + 'a' * 64


def attestation_line(predicate, digest=DIGEST, predicate_type=None, extra=None):
    statement = {
        '_type': 'https://in-toto.io/Statement/v0.1',
        'subject': [{'name': 'ghcr.io/o/r', 'digest': {'sha256': digest[7:]}}],
        'predicateType': predicate_type or sbom_identity.CYCLONEDX_PREDICATE_TYPE,
        'predicate': predicate,
    }
    statement.update(extra or {})
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return json.dumps({'payload': payload, 'signatures': []})


def test_attestation_must_carry_the_validated_sbom():
    sbom, _ = fixture('amd64')
    expected = (DIGEST, len(sbom['components']), sbom_identity.canonical_sha256(sbom))
    assert sbom_identity.check_attestations(attestation_line(sbom), *expected) == 1
    other = copy.deepcopy(sbom)
    other['components'][0]['version'] = '9.9.9'
    fewer = copy.deepcopy(sbom)
    fewer['components'].pop()
    for line, message in [
        (attestation_line(other), 'prédicat attesté'),
        (attestation_line(fewer), 'nombre de composants'),
        (attestation_line(sbom, digest='sha256:' + 'b' * 64), 'sujet'),
        (attestation_line(sbom, predicate_type='https://slsa.dev/provenance/v1'),
         'type de prédicat'),
        (attestation_line(sbom, extra={'subject': []}), 'sujet'),
        ('', 'aucune attestation'),
    ]:
        with pytest.raises(ValueError, match=message):
            sbom_identity.check_attestations(line, *expected)


def jobs():
    body = WORKFLOW.split('\njobs:\n', 1)[1]
    parts = re.split(r'^  ([a-z0-9-]+):\n', body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def test_permissions_are_confined_to_the_jobs_that_need_them():
    blocks = jobs()
    assert [k for k, v in blocks.items() if 'id-token: write' in v] == ['release']
    assert [k for k, v in blocks.items() if 'packages: write' in v] == [
        'build-amd64', 'build-arm64', 'release', 'promote']
    assert 'permissions: {}' in blocks['admission']
    assert 'permissions: {}' in blocks['verify-publication']
    # Un workflow réutilisable changerait le SAN : on signe depuis ci.yaml.
    assert 'uses: ./' not in blocks['release']
    assert 'cosign' not in blocks['release'].replace('sign_release.sh', '').replace(
        'install_tools.sh crane cosign', '')


@pytest.mark.parametrize('arch', ['amd64', 'arm64'])
def test_registry_cache_is_written_on_push_only(arch):
    block = jobs()[f'build-{arch}']
    assert "cache-write: ${{ github.event_name == 'push' }}" in block
    assert 'secrets:' not in block and 'pull_request' not in block


def test_admission_is_blocking_and_gates_the_publication_check():
    blocks = jobs()
    admission = blocks['admission']
    assert 'needs: release\n' in admission
    for forbidden in ('continue-on-error', '|| true', 'download-artifact',
                      'secrets.', 'GITHUB_TOKEN', 'packages:'):
        assert forbidden not in admission
    assert 'needs: [release, admission]\n' in blocks['promote']
    assert re.search(r'needs: \[release, promote,', blocks['verify-publication'])


def test_release_signs_before_any_release_tag():
    release = jobs()['release']
    order = [release.index(marker) for marker in (
        'verify_sbom.sh amd64', 'verify_sbom.sh arm64',
        'scripts/ci/publish_index.sh', 'scripts/ci/sign_release.sh', 'docker logout')]
    assert order == sorted(order)
    assert 'scan-amd64.outputs.sbom-artifact-id' in release
    assert 'steps.push.outputs.amd64_digest' in release
    assert 'promote_tags.sh' not in release
    publish = (ROOT / 'scripts/ci/publish_index.sh').read_text()
    assert 'crane tag' not in publish


def test_required_checks_keep_their_names():
    names = re.findall(r'^    name: (.+)$', WORKFLOW, flags=re.M)
    for required in ('Flake8 + tests unitaires', 'Hadolint + pinning',
                     'BuildKit + Dive', 'Trivy', 'Compose + pytest'):
        assert required in names


def test_admission_identity_is_this_workflow_file():
    script = (ROOT / 'scripts/ci/admit_release.sh').read_text()
    assert '.github/workflows/ci.yaml@$GITHUB_REF' in script
    assert 'https://token.actions.githubusercontent.com' in script


def test_cosign_is_pinned_to_an_official_release_checksum():
    installer = (ROOT / 'scripts/ci/install_tools.sh').read_text()
    assert re.search(
        r'cosign\) install_binary https://github\.com/sigstore/cosign/releases/'
        r'download/v3\.1\.4/cosign-linux-amd64 [0-9a-f]{64} cosign ;;', installer)


needs_registry = pytest.mark.skipif(
    not os.environ.get('TP2_TEST_REGISTRY')
    or not all(shutil.which(t) for t in ('docker', 'cosign', 'crane', 'syft')),
    reason='TP2_TEST_REGISTRY (ex. localhost:5001) et docker/cosign/crane/syft requis')


def run(args, cwd, env, check=True):
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def key_pair(directory, env):
    directory.mkdir()
    run(['cosign', 'generate-key-pair'], directory, env)
    run(['cosign', 'signing-config', 'create', '--out', 'signing-config.json'],
        directory, env)
    return directory


def prepare_arch(root, env, arch):
    """Vraie archive busybox, vraie SBOM Syft, identité vérifiée comme en CI."""
    (root / 'dist' / arch).mkdir(parents=True)
    (root / 'dist/sbom' / arch).mkdir(parents=True)
    run(['docker', 'pull', '-q', '--platform', f'linux/{arch}', 'busybox:1.37'],
        root, env)
    run(['docker', 'save', '--platform', f'linux/{arch}', '-o',
         f'dist/{arch}/image.tar', 'busybox:1.37'], root, env)
    sbom = f'dist/sbom/{arch}/sbom.cdx.json'
    image = run(['python3', 'scripts/ci/image_archive.py', 'describe',
                 f'dist/{arch}/image.tar'], root, env).stdout
    (root / f'{arch}.json').write_text(image)
    run(['syft', 'scan', f'docker-archive:dist/{arch}/image.tar',
         '--source-version', json.loads(image)['image_id'], '-o',
         f'cyclonedx-json={sbom}', '-q'], root, env)
    run(['python3', 'scripts/ci/sbom_identity.py', 'verify', '--sbom', sbom,
         '--image-json', f'{arch}.json', '--arch', arch,
         '--github-output', f'{arch}.out'], root, env)
    outputs = (root / f'{arch}.out').read_text().split()
    values = dict(line.split('=') for line in outputs)
    upper = arch.upper()
    env[f'{upper}_ID'] = json.loads(image)['image_id']
    env[f'{upper}_SBOM_COMPONENTS'] = values['components']
    env[f'{upper}_SBOM_SHA256'] = values['sha256']


@needs_registry
def test_local_registry_key_mode(tmp_path):
    """Publication, signature récursive, attestations puis admission (clé jetable).

    Le mode keyless (Fulcio, Rekor, SAN du certificat) n'est pas couvert : il
    exige l'OIDC d'un vrai run GitHub Actions.
    """
    shutil.copytree(ROOT / 'scripts', tmp_path / 'scripts')
    # Dépôt unique par exécution : publish_index.sh refuse une version existante.
    repository = f'{os.environ["TP2_TEST_REGISTRY"]}/tp2-test/{uuid.uuid4().hex[:12]}'
    env = dict(os.environ, COSIGN_PASSWORD='pw', GITHUB_ACTIONS='',
               REPOSITORY=repository, VERSION='1.2.3',
               MINOR='1.2', MAJOR='1', GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1',
               GITHUB_OUTPUT=str(tmp_path / 'out'), GITHUB_SHA='a' * 40,
               GITHUB_REPOSITORY='maximilianpw/devsecops-max-jb',
               GITHUB_REF='refs/tags/v1.2.3')
    keys = key_pair(tmp_path / 'keys', env)
    stranger = key_pair(tmp_path / 'stranger', env)
    for arch in ('amd64', 'arm64'):
        prepare_arch(tmp_path, env, arch)
    run(['scripts/ci/publish_index.sh'], tmp_path, env)
    published = dict(line.split('=') for line in (tmp_path / 'out').read_text().split())
    env.update(
        INDEX_DIGEST=published['digest'], AMD64_DIGEST=published['amd64_digest'],
        ARM64_DIGEST=published['arm64_digest'],
        COSIGN_SIGN_TEST_ARGS=(f'--key {keys}/cosign.key '
                               f'--signing-config {keys}/signing-config.json'),
        COSIGN_VERIFY_TEST_ARGS=f'--key {keys}/cosign.pub --insecure-ignore-tlog')
    run(['scripts/ci/sign_release.sh'], tmp_path, env)
    admit = ['scripts/ci/admit_release.sh']
    run(admit, tmp_path, env)

    wrong_key = dict(env, COSIGN_VERIFY_TEST_ARGS=(
        f'--key {stranger}/cosign.pub --insecure-ignore-tlog'))
    wrong_sbom = dict(env, AMD64_SBOM_SHA256=env['ARM64_SBOM_SHA256'])
    for broken in (wrong_key, wrong_sbom):
        assert run(admit, tmp_path, broken, check=False).returncode != 0
    run(['scripts/ci/promote_tags.sh'], tmp_path, env)
    for tag in ('1.2.3', '1.2', '1'):
        digest = run(['crane', 'digest', f'{repository}:{tag}'], tmp_path, env)
        assert digest.stdout.strip() == env['INDEX_DIGEST']


def test_sbom_rejects_another_image_sharing_dependency_layers():
    sbom, image = fixture('amd64')
    sbom['metadata']['component']['version'] = image['image_id']
    image['image_id'] = 'sha256:' + 'f' * 64
    image['diff_ids'].append('sha256:' + 'e' * 64)
    with pytest.raises(ValueError, match='config digest'):
        sbom_identity.check_sbom(sbom, image, 'amd64')
