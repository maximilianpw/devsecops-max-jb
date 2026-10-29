"""Exercise CI shell entrypoints with failing tools, without Docker or a registry."""

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parent.parent
TOKEN = b'TP2_' + b'a' * 48


@pytest.fixture
def sandbox(tmp_path):
    shutil.copytree(ROOT / 'scripts', tmp_path / 'scripts')
    for name in ('Dockerfile', '.dockerignore', 'requirements.txt', 'app.py'):
        shutil.copyfile(ROOT / name, tmp_path / name)
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ['PATH'],
               CALLS=str(tmp_path / 'calls.jsonl'), TEST_ROOT=str(tmp_path),
               IMAGE='flask-api:test', EXPECTED_PLATFORM='linux/arm64',
               ARCH='arm64', GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123',
               GITHUB_RUN_ATTEMPT='1', GITHUB_OUTPUT=str(tmp_path / 'outputs'))
    return tmp_path, env


def stub(root, name, body):
    path = root / 'bin' / name
    path.write_text(f'#!{sys.executable}\n' + body)
    path.chmod(0o755)


def execute(root, env, script):
    return subprocess.run(['bash', str(root / 'scripts/ci' / script)],
                          cwd=root, env=env, capture_output=True, timeout=30)


def calls(root):
    lines = (root / 'calls.jsonl').read_text().splitlines()
    return [json.loads(line) for line in lines]


@pytest.mark.parametrize('up_code,down_code', [(7, 0), (7, 8), (0, 8)])
def test_integration_cleanup_survives_diagnostic_failure(sandbox, up_code, down_code):
    root, env = sandbox
    env.update(UP_CODE=str(up_code), DOWN_CODE=str(down_code))
    stub(root, 'docker', r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(args) + '\n')
if 'up' in args:
    sys.exit(int(os.environ['UP_CODE']))
if 'logs' in args:
    sys.exit(9)
if 'down' in args:
    sys.exit(int(os.environ['DOWN_CODE']))
if 'ps' in args:
    print('container-id')
elif 'inspect' in args:
    print('healthy' if 'Health' in ' '.join(args) else 'sha256:test')
elif 'exec' in args:
    print('aarch64')
''')
    # No real pytest/HTTP needed: only the script's failure and teardown paths.
    stub(root, 'test-python', 'raise SystemExit(0)\n')
    env['PYTHON'] = str(root / 'bin/test-python')
    result = execute(root, env, 'test_variant.sh')
    recorded = calls(root)
    assert result.returncode == (up_code or 1)
    assert any('down' in call for call in recorded)
    if up_code:
        assert any('logs' in call for call in recorded)
    override = next(arg for call in recorded for arg in call
                    if arg.endswith('/override.yaml'))
    assert not Path(override).parent.exists()


@pytest.mark.parametrize('failure', [
    'api-gate', 'dependency-report', 'db-gate', 'grype-gate', 'empty-sbom', 'none',
])
def test_scans_collect_remaining_reports_and_gates(sandbox, failure):
    root, env = sandbox
    env['FAIL_SCAN'] = failure
    env['EXPECTED_IMAGE_ID'] = 'sha256:' + 'd' * 64
    # Archive verification remains a fail-fast prerequisite, outside scan aggregation.
    (root / 'scripts/ci/load_verified_image.sh').write_text('#!/bin/sh\nexit 0\n')
    stub(root, 'dive', 'raise SystemExit(0)\n')
    stub(root, 'syft', r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(args) + '\n')
empty = os.environ['FAIL_SCAN'] == 'empty-sbom'
documents = {'cyclonedx-json': {'components': [] if empty else [{'purl': 'pkg:x'}]},
             'spdx-json': {'packages': [] if empty else [{'licenseConcluded': 'MIT'}]}}
for value in args[args.index('-o') + 1::2]:
    fmt, path = value.split('=', 1)
    Path(path).write_text(json.dumps(documents[fmt]))
''')
    stub(root, 'grype', r'''import json, os, sys
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(sys.argv[1:]) + '\n')
sys.exit(1 if os.environ['FAIL_SCAN'] == 'grype-gate' else 0)
''')
    stub(root, 'docker', 'print(\'{"services":{"db":{"image":"postgres@test"}}}\')\n')
    stub(root, 'trivy', r'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(args) + '\n')
if '--output' in args:
    output = Path(args[args.index('--output') + 1])
    output.parent.mkdir(parents=True, exist_ok=True)
    finding = {'RuleID': 'tp2-build-token'}
    output.write_text(json.dumps({'Results': [{'Secrets': [finding]}]}))
if args[0] == 'fs' and 'secret' in args:
    sys.exit(1)  # Positive control must be detected.
failure = os.environ['FAIL_SCAN']
if (failure == 'api-gate' and 'dist/image.tar' in args
        and 'vuln' in args and '--exit-code' in args):
    sys.exit(1)
if failure == 'dependency-report' and 'reports/trivy-deps-full.json' in args:
    sys.exit(2)
if failure == 'db-gate' and '--image-src' in args and '--exit-code' in args:
    sys.exit(1)
''')
    result = execute(root, env, 'scan_variant.sh')
    recorded = calls(root)
    sbom_call = next(call for call in recorded if call[:1] == ['scan'])
    assert (sbom_call[sbom_call.index('--source-version') + 1]
            == env['EXPECTED_IMAGE_ID'])
    assert (result.returncode == 0) == (failure == 'none'), result.stderr
    reports = ('trivy-image-full.json', 'trivy-deps-full.json', 'trivy-db-full.json')
    for report in reports:
        assert any('reports/' + report in call for call in recorded)
    assert any(call[0] == 'fs' and 'vuln' in call and '--exit-code' in call
               for call in recorded)
    assert any('--image-src' in call and '--exit-code' in call for call in recorded)
    assert ['sbom:reports/sbom/sbom.cdx.json', '--config', '.grype.yaml'] in recorded
    assert any('--only-fixed=false' in call for call in recorded)


def make_image(path, arch='arm64'):
    # Empty image is sufficient for the real image_archive.describe boundary.
    config = json.dumps({'os': 'linux', 'architecture': arch,
                         'rootfs': {'type': 'layers', 'diff_ids': []}}).encode()
    manifest = [{'Config': 'config.json', 'Layers': []}]
    files = {'config.json': config, 'manifest.json': json.dumps(manifest).encode()}
    with tarfile.open(path, 'w') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@pytest.mark.parametrize('scenario', [
    'clean', 'leak', 'early-failure', 'safe-failure',
])
def test_build_only_publishes_audited_logs(sandbox, scenario):
    root, env = sandbox
    make_image(root / 'fixture.tar')
    env['BUILD_SCENARIO'] = scenario
    stub(root, 'git', 'raise SystemExit(0)\n')
    stub(root, 'openssl', "print('a' * 48)\n")
    stub(root, 'docker', r'''import os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
if args[:2] == ['buildx', 'build']:
    if args[-1].endswith('pipctx'):
        print('Using cached dependency')
    elif '--secret' in args:
        print('Build secret package_token must not be empty')
        sys.exit(1)
    elif args[-1] == '.':
        print('secret package_token: not found')
        sys.exit(1)
    else:
        print('secrets/build_token: not found')
        sys.exit(1)
elif args[:2] == ['buildx', 'bake']:
    if os.environ['BUILD_SCENARIO'] == 'safe-failure':
        print('network unavailable')
        sys.exit(17)
    if os.environ['BUILD_SCENARIO'] in ('leak', 'early-failure'):
        print(Path(os.environ['BUILD_SECRET_FILE']).read_text())
        if os.environ['BUILD_SCENARIO'] == 'early-failure':
            sys.exit(17)
    if any('cache-to=' in arg for arg in args):
        blobs = Path('dist/layer-cache/blobs/sha256')
        blobs.mkdir(parents=True)
        (blobs / 'abc').write_text('clean cache')
    print('CACHED')
elif args[0] == 'save':
    source = Path(os.environ['TEST_ROOT']) / 'fixture.tar'
    shutil.copyfile(source, args[args.index('--output') + 1])
else:
    print('test tool')
''')
    result = execute(root, env, 'build_variant.sh')
    assert (result.returncode == 0) == (scenario == 'clean'), result.stderr
    assert TOKEN not in result.stdout + result.stderr
    logs = list((root / 'reports').glob('*'))
    assert all(TOKEN not in log.read_bytes() for log in logs)
    if scenario == 'clean':
        assert (root / 'reports/build.log').is_file()
        assert 'run_attempt=1' in (root / 'outputs').read_text()
    elif scenario == 'safe-failure':
        assert result.returncode == 17
        assert (root / 'reports/build.log').read_text() == 'network unavailable\n'
    else:
        assert not (root / 'reports/build.log').exists()


@pytest.mark.parametrize('leaks', [True, False])
def test_log_publication_copies_only_audited_bytes(tmp_path, leaks):
    secret = tmp_path / 'token'
    secret.write_bytes(TOKEN)
    clean = tmp_path / 'clean.log'
    clean.write_text('safe diagnostic')
    second = tmp_path / 'second.log'
    second.write_bytes(TOKEN if leaks else b'other safe diagnostic')
    destination = tmp_path / 'publishable'
    result = subprocess.run([
        sys.executable, str(ROOT / 'scripts/ci/audit_secret.py'), str(secret),
        str(clean), str(second), '--publish-to', str(destination),
    ], capture_output=True)
    assert (result.returncode == 0) == (not leaks)
    assert TOKEN not in result.stdout + result.stderr
    if leaks:
        assert 'fuite détectée' in result.stderr.decode()
        assert not (destination / second.name).exists()
        assert (destination / 'second.log.withheld').is_file()
    else:
        assert (destination / second.name).read_bytes() == second.read_bytes()
    assert (destination / clean.name).read_bytes() == clean.read_bytes()


def test_log_publication_copies_the_bytes_it_checked(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        'audit_secret', ROOT / 'scripts/ci/audit_secret.py')
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    source = tmp_path / 'build.log'
    source.write_bytes(b'safe diagnostic')
    read_bytes = Path.read_bytes

    def read_then_change(path):
        data = read_bytes(path)
        if path == source:
            path.write_bytes(TOKEN)
        return data

    monkeypatch.setattr(Path, 'read_bytes', read_then_change)
    destination = tmp_path / 'reports'
    assert audit.publish(TOKEN, [source], destination) == []
    assert (destination / source.name).read_bytes() == b'safe diagnostic'


SIGNING_IDENTITY = ('https://github.com/maximilianpw/devsecops-max-jb/'
                    '.github/workflows/ci.yaml@refs/tags/v1.2.0')
REPO = 'ghcr.io/maximilianpw/devsecops-max-jb'
INDEX, AMD64, ARM64 = ('sha256:' + c * 64 for c in 'abc')
SBOMS = ROOT / 'tests/fixtures/sbom'

# One fake registry/Sigstore for crane and cosign, driven by files in `registry/`:
# `identity` is the only certificate identity it accepts, `attestations/<hex>`
# holds the verify-attestation output served for a manifest digest.
CRANE = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
registry = Path(os.environ['TEST_ROOT']) / 'registry'
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(['crane'] + args) + '\n')
if args[0] == 'digest':
    tags = json.loads((registry / 'tags.json').read_text())
    print(tags[args[1].split(':')[-1]])
elif args[0] == 'manifest':
    print((registry / 'index.json').read_text())
"""

COSIGN = r"""import json, os, sys
from pathlib import Path
args = sys.argv[1:]
registry = Path(os.environ['TEST_ROOT']) / 'registry'
with open(os.environ['CALLS'], 'a') as out:
    out.write(json.dumps(['cosign'] + args) + '\n')
if args[0] in ('verify', 'verify-attestation'):
    identity = args[args.index('--certificate-identity') + 1]
    if identity != (registry / 'identity').read_text():
        sys.exit('no matching signatures: identity mismatch')
if args[0] == 'verify-attestation':
    served = registry / 'attestations' / args[-1].split('sha256:')[1]
    if not served.exists():
        sys.exit('none of the attestations matched the predicate type: cyclonedx')
    print(served.read_text())
"""

PUBLISH_CRANE = r"""import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ['TEST_ROOT'])
ids = json.loads(os.environ['IMAGE_IDS'])
digests = {'amd64': os.environ['AMD64'], 'arm64': os.environ['ARM64']}
if args[0] == 'digest':
    ref = args[1]
    if ref.endswith(('-amd64', '-arm64')):
        print(digests[ref.rsplit('-', 1)[-1]])
    elif ref.endswith('-index') or Path(os.environ['TAGGED']).exists():
        print(os.environ['INDEX'])
    else:
        sys.exit('MANIFEST_UNKNOWN')
elif args[0] in ('manifest', 'pull'):
    ref = args[1]
    if ref.endswith('-index'):
        print(json.dumps({'manifests': [
            {'platform': {'os': 'linux', 'architecture': a}, 'digest': d}
            for a, d in digests.items()]}))
        sys.exit(0)
    arch = [a for a, d in digests.items() if d == ref.split('@')[1]][0]
    if args[0] == 'manifest':
        print(json.dumps({'config': {'digest': ids[arch]}}))
    else:
        shutil.copyfile(root / (arch + '.tar'), args[2])
elif args[0] == 'tag':
    Path(os.environ['TAGGED']).write_text('1')
"""


def statement_line(sbom, digest):
    statement = {
        '_type': 'https://in-toto.io/Statement/v0.1',
        'subject': [{'name': REPO, 'digest': {'sha256': digest[7:]}}],
        'predicateType': 'https://cyclonedx.org/bom', 'predicate': sbom,
    }
    return json.dumps({'payload': base64.b64encode(
        json.dumps(statement).encode()).decode()})


def canonical(sbom):
    return hashlib.sha256(json.dumps(
        sbom, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@pytest.fixture
def release(sandbox):
    """Sandbox with a fake registry holding a signed, attested release."""
    root, env = sandbox
    stub(root, 'crane', CRANE)
    stub(root, 'cosign', COSIGN)
    registry = root / 'registry'
    (registry / 'attestations').mkdir(parents=True)
    (registry / 'identity').write_text(SIGNING_IDENTITY)
    tags = {'1.2.0': INDEX, '1.2': INDEX, '1': INDEX}
    (registry / 'tags.json').write_text(json.dumps(tags))
    manifests = [{'platform': {'os': 'linux', 'architecture': arch}, 'digest': d}
                 for arch, d in (('amd64', AMD64), ('arm64', ARM64))]
    (registry / 'index.json').write_text(json.dumps({'manifests': manifests}))
    sboms = {arch: json.loads((SBOMS / f'{arch}.cdx.json').read_text())
             for arch in ('amd64', 'arm64')}
    for arch, digest in (('amd64', AMD64), ('arm64', ARM64)):
        (registry / 'attestations' / digest[7:]).write_text(
            statement_line(sboms[arch], digest))
        (root / f'dist/sbom/{arch}').mkdir(parents=True)
        shutil.copyfile(SBOMS / f'{arch}.cdx.json',
                        root / f'dist/sbom/{arch}/sbom.cdx.json')
    env.update(
        REPOSITORY=REPO, VERSION='1.2.0', MINOR='1.2', MAJOR='1',
        INDEX_DIGEST=INDEX, AMD64_DIGEST=AMD64, ARM64_DIGEST=ARM64,
        AMD64_SBOM_COMPONENTS=str(len(sboms['amd64']['components'])),
        AMD64_SBOM_SHA256=canonical(sboms['amd64']),
        ARM64_SBOM_COMPONENTS=str(len(sboms['arm64']['components'])),
        ARM64_SBOM_SHA256=canonical(sboms['arm64']),
        GITHUB_REPOSITORY='maximilianpw/devsecops-max-jb',
        GITHUB_REF='refs/tags/v1.2.0', GITHUB_ACTIONS='')
    return root, env


def cosign_calls(root):
    if not (root / 'calls.jsonl').exists():
        return []
    return [call for call in calls(root) if call[0] == 'cosign']


def test_signing_targets_digests_only(release):
    root, env = release
    result = execute(root, env, 'sign_release.sh')
    assert result.returncode == 0, result.stderr
    recorded = cosign_calls(root)
    assert [call[:2] for call in recorded] == [
        ['cosign', 'sign'], ['cosign', 'attest'], ['cosign', 'attest']]
    assert '--recursive' in recorded[0] and recorded[0][-1] == f'{REPO}@{INDEX}'
    for call, digest, arch in zip(recorded[1:], (AMD64, ARM64), ('amd64', 'arm64')):
        assert call[-1] == f'{REPO}@{digest}'
        assert call[call.index('--predicate') + 1] == (
            f'dist/sbom/{arch}/sbom.cdx.json')
        assert call[call.index('--type') + 1] == 'cyclonedx'
    # Never a tag: every reference handed to cosign is `repository@sha256:<64 hex>`.
    assert all(call[-1].startswith(REPO + '@sha256:') for call in recorded)


@pytest.mark.parametrize('change', [
    {'AMD64_DIGEST': ''},
    {'ARM64_DIGEST': 'latest'},
    {'INDEX_DIGEST': 'sha256:abc'},
    {'AMD64_DIGEST': INDEX},
    {'REPOSITORY': REPO + ':1.2.0'},
    {'ARM64_DIGEST': 'sha256:' + 'd' * 64},
], ids=['missing', 'tag', 'short', 'duplicate', 'repository-tag', 'not-in-index'])
def test_signing_never_starts_without_valid_digests(release, change):
    root, env = release
    env.update(change)
    assert execute(root, env, 'sign_release.sh').returncode != 0
    assert cosign_calls(root) == []


def test_signing_refuses_a_missing_sbom_before_any_cosign_call(release):
    root, env = release
    (root / 'dist/sbom/arm64/sbom.cdx.json').unlink()
    assert execute(root, env, 'sign_release.sh').returncode != 0
    assert cosign_calls(root) == []


def test_test_only_key_mode_is_refused_in_ci(release):
    root, env = release
    env.update(GITHUB_ACTIONS='true', COSIGN_SIGN_TEST_ARGS='--key x',
               COSIGN_VERIFY_TEST_ARGS='--key x')
    assert execute(root, env, 'sign_release.sh').returncode != 0
    assert execute(root, env, 'admit_release.sh').returncode != 0
    assert cosign_calls(root) == []


def test_admission_accepts_the_signed_release(release):
    root, env = release
    result = execute(root, env, 'admit_release.sh')
    assert result.returncode == 0, result.stderr
    verify = [c for c in cosign_calls(root) if c[1] == 'verify']
    attest = [c for c in cosign_calls(root) if c[1] == 'verify-attestation']
    assert [c[-1] for c in verify] == [f'{REPO}@{d}' for d in (INDEX, AMD64, ARM64)]
    assert [c[-1] for c in attest] == [f'{REPO}@{AMD64}', f'{REPO}@{ARM64}']
    for call in verify + attest:
        assert call[call.index('--certificate-identity') + 1] == SIGNING_IDENTITY
        assert call[call.index('--certificate-oidc-issuer') + 1] == (
            'https://token.actions.githubusercontent.com')
    assert all(c[c.index('--type') + 1] == 'cyclonedx' for c in attest)


@pytest.mark.parametrize('change', [
    {'GITHUB_REF': 'refs/tags/v1.2.1'},
    {'GITHUB_REPOSITORY': 'someone-else/devsecops-max-jb'},
], ids=['other-tag', 'other-repository'])
def test_admission_fails_on_a_wrong_signing_identity(release, change):
    root, env = release
    env.update(change)
    result = execute(root, env, 'admit_release.sh')
    assert result.returncode != 0
    assert b'identity mismatch' in result.stderr


def test_admission_fails_when_an_attestation_is_missing(release):
    root, env = release
    (root / 'registry/attestations' / ARM64[7:]).unlink()
    result = execute(root, env, 'admit_release.sh')
    assert result.returncode != 0
    assert b'none of the attestations matched' in result.stderr


def test_admission_rejects_an_sbom_from_another_architecture(release):
    root, env = release
    amd64 = json.loads((SBOMS / 'amd64.cdx.json').read_text())
    (root / 'registry/attestations' / ARM64[7:]).write_text(
        statement_line(amd64, ARM64))
    result = execute(root, env, 'admit_release.sh')
    assert result.returncode != 0
    assert 'prédicat attesté' in result.stderr.decode()


def test_admission_fails_when_a_tag_no_longer_points_to_the_signed_index(release):
    root, env = release
    (root / 'registry/tags.json').write_text(json.dumps(
        {'1.2.0': INDEX, '1.2': AMD64, '1': INDEX}))
    assert execute(root, env, 'admit_release.sh').returncode != 0
    assert cosign_calls(root) == []


@pytest.mark.parametrize('missing', [
    'AMD64_DIGEST', 'ARM64_DIGEST', 'AMD64_SBOM_SHA256', 'ARM64_SBOM_COMPONENTS'])
def test_admission_requires_every_expected_output(release, missing):
    root, env = release
    env[missing] = ''
    assert execute(root, env, 'admit_release.sh').returncode != 0
    assert cosign_calls(root) == []


@pytest.mark.parametrize('sbom_arch', ['amd64', 'arm64'])
def test_sbom_of_another_arch_stops_the_release_before_publication(
        tmp_path, sbom_arch):
    # Real Syft output: the arm64 SBOM must not validate the amd64 image.
    sbom = json.loads((SBOMS / f'{sbom_arch}.cdx.json').read_text())
    image = json.loads((SBOMS / f'{sbom_arch}.image.json').read_text())
    sbom['metadata']['component']['version'] = image['image_id']
    source = tmp_path / 'sbom.cdx.json'
    source.write_text(json.dumps(sbom))
    result = subprocess.run([
        sys.executable, str(ROOT / 'scripts/ci/sbom_identity.py'), 'verify',
        '--sbom', str(source),
        '--image-json', str(SBOMS / 'amd64.image.json'), '--arch', 'amd64',
        '--github-output', str(tmp_path / 'out')], capture_output=True)
    accepted = sbom_arch == 'amd64'
    assert (result.returncode == 0) == accepted, result.stderr
    assert (tmp_path / 'out').exists() == accepted


def test_publish_outputs_the_platform_digests(sandbox):
    root, env = sandbox
    image_ids = {}
    for arch in ('amd64', 'arm64'):
        make_image(root / f'{arch}.tar', arch)
        (root / 'dist' / arch).mkdir(parents=True)
        shutil.copyfile(root / f'{arch}.tar', root / 'dist' / arch / 'image.tar')
        described = subprocess.run(
            [sys.executable, str(root / 'scripts/ci/image_archive.py'),
             'describe', str(root / f'{arch}.tar')], capture_output=True)
        image_ids[arch] = json.loads(described.stdout)['image_id']
    env.update(REPOSITORY=REPO, VERSION='1.2.0', MINOR='1.2', MAJOR='1',
               AMD64_ID=image_ids['amd64'], ARM64_ID=image_ids['arm64'],
               INDEX=INDEX, AMD64=AMD64, ARM64=ARM64,
               TAGGED=str(root / 'tagged'), IMAGE_IDS=json.dumps(image_ids))
    stub(root, 'crane', PUBLISH_CRANE)
    stub(root, 'docker', 'raise SystemExit(0)\n')
    result = execute(root, env, 'publish_index.sh')
    assert result.returncode == 0, result.stderr
    published = dict(line.split('=') for line in
                     (root / 'outputs').read_text().split())
    assert published == {'digest': INDEX, 'amd64_digest': AMD64,
                         'arm64_digest': ARM64}


def test_admission_fails_when_the_index_does_not_hold_the_attested_manifests(
        release):
    root, env = release
    other = [{'platform': {'os': 'linux', 'architecture': arch}, 'digest': digest}
             for arch, digest in (('amd64', AMD64), ('arm64', 'sha256:' + 'e' * 64))]
    (root / 'registry/index.json').write_text(json.dumps({'manifests': other}))
    assert execute(root, env, 'admit_release.sh').returncode != 0
    assert cosign_calls(root) == []


def make_layered_image(path, arch, marker):
    """Docker archive with one real layer, so DiffIDs are genuine."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as inner:
        data = marker.encode()
        member = tarfile.TarInfo('marker')
        member.size = len(data)
        inner.addfile(member, io.BytesIO(data))
    layer_bytes = layer.getvalue()
    diff_id = 'sha256:' + hashlib.sha256(layer_bytes).hexdigest()
    config = json.dumps({'os': 'linux', 'architecture': arch, 'rootfs': {
        'type': 'layers', 'diff_ids': [diff_id]}}).encode()
    manifest = [{'Config': 'config.json', 'Layers': ['layer.tar']}]
    files = {'config.json': config, 'layer.tar': layer_bytes,
             'manifest.json': json.dumps(manifest).encode()}
    with tarfile.open(path, 'w') as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return 'sha256:' + hashlib.sha256(config).hexdigest(), diff_id


def sbom_for(diff_id, image_id):
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.7',
            'metadata': {'component': {'type': 'container', 'name': 'image.tar',
                                       'version': image_id}},
            'components': [{'name': 'busybox', 'properties': [
                {'name': 'syft:location:0:layerID', 'value': diff_id}]}]}


@pytest.fixture
def sbom_release(sandbox):
    """Verified amd64/arm64 archives and their SBOM artifacts, as in `release`."""
    root, env = sandbox
    ids = {}
    for arch in ('amd64', 'arm64'):
        (root / 'dist' / arch).mkdir(parents=True)
        (root / 'dist/sbom' / arch).mkdir(parents=True)
        ids[arch], diff_id = make_layered_image(
            root / 'dist' / arch / 'image.tar', arch, arch)
        for name in ('sbom.cdx.json', 'sbom.spdx.json'):
            (root / 'dist/sbom' / arch / name).write_text(
                json.dumps(sbom_for(diff_id, ids[arch])))
    stub(root, 'curl', r"""import os, sys
args = sys.argv[1:]
open(args[args.index('-o') + 1], 'w').write(os.environ['ARTIFACT_JSON'])
""")
    env.update(
        GH_TOKEN='token', GITHUB_REPOSITORY='maximilianpw/devsecops-max-jb',
        SBOM_ARTIFACT_ID='4242', EXPECTED_IMAGE_ID=ids['amd64'],
        ARTIFACT_JSON=json.dumps({
            'id': 4242, 'name': 'sbom-amd64-1', 'expired': False,
            'workflow_run': {'id': 123, 'head_sha': 'a' * 40}}))
    return root, env, ids


def verify_sbom(root, env, arch='amd64'):
    return subprocess.run(
        ['bash', str(root / 'scripts/ci/verify_sbom.sh'), arch],
        cwd=root, env=env, capture_output=True, timeout=30)


def test_sbom_verification_publishes_count_and_hash(sbom_release):
    root, env, _ = sbom_release
    result = verify_sbom(root, env)
    assert result.returncode == 0, result.stderr
    published = dict(line.split('=') for line in
                     (root / 'outputs').read_text().split())
    assert published['components'] == '1'
    assert published['sha256'] == canonical(json.loads(
        (root / 'dist/sbom/amd64/sbom.cdx.json').read_text()))


def test_sbom_of_the_other_architecture_is_rejected_by_the_release_step(
        sbom_release):
    root, env, ids = sbom_release
    shutil.copyfile(root / 'dist/sbom/arm64/sbom.cdx.json',
                    root / 'dist/sbom/amd64/sbom.cdx.json')
    result = verify_sbom(root, env)
    assert result.returncode != 0
    assert 'absentes de l’image' in result.stderr.decode()
    assert not (root / 'outputs').exists()


@pytest.mark.parametrize('change,message', [
    ({'workflow_run': {'id': 7, 'head_sha': 'a' * 40}}, 'autre run'),
    ({'workflow_run': {'id': 123, 'head_sha': 'b' * 40}}, 'autre commit'),
    ({'name': 'sbom-arm64-1'}, 'nom d’artefact'),
    ({'id': 4243}, 'ID d’artefact'),
    ({'expired': True}, 'expiré'),
])
def test_sbom_artifact_identity_comes_from_the_github_api(
        sbom_release, change, message):
    root, env, _ = sbom_release
    env['ARTIFACT_JSON'] = json.dumps(dict(json.loads(env['ARTIFACT_JSON']), **change))
    result = verify_sbom(root, env)
    assert result.returncode != 0
    assert message in result.stderr.decode()
    assert not (root / 'outputs').exists()


@pytest.mark.parametrize('removed', ['sbom.spdx.json', 'sbom.cdx.json'])
def test_sbom_artifact_must_hold_both_formats(sbom_release, removed):
    root, env, _ = sbom_release
    (root / 'dist/sbom/amd64' / removed).unlink()
    assert verify_sbom(root, env).returncode != 0
    assert not (root / 'outputs').exists()


def test_sbom_step_fails_closed_without_the_artifact_id(sbom_release):
    # Contract with the SBOM PR not honoured yet: no `sbom-artifact-id` output.
    root, env, _ = sbom_release
    env['SBOM_ARTIFACT_ID'] = ''
    assert verify_sbom(root, env).returncode != 0


def test_sbom_step_rejects_an_image_id_that_differs_from_the_build_output(
        sbom_release):
    root, env, ids = sbom_release
    env['EXPECTED_IMAGE_ID'] = ids['arm64']
    assert verify_sbom(root, env).returncode != 0


@pytest.mark.parametrize('cache_write,event,ref,allowed', [
    ('true', 'push', 'refs/heads/main', True),
    ('true', 'push', 'refs/tags/v1.2.0', True),
    ('true', 'push', 'refs/heads/main-evil', False),
    ('true', 'push', 'refs/heads/feature', False),
    ('true', 'pull_request', 'refs/heads/main', False),
    ('true', 'pull_request', 'refs/pull/12/merge', False),
    ('true', 'pull_request_target', 'refs/heads/main', False),
    ('false', 'push', 'refs/heads/main', False),
    ('', 'push', 'refs/tags/v1.2.0', False),
])
def test_cache_export_requires_explicit_trusted_push(
        sandbox, cache_write, event, ref, allowed):
    root, env = sandbox
    make_image(root / 'fixture.tar')
    env.update(CACHE_WRITE=cache_write, GITHUB_EVENT_NAME=event, GITHUB_REF=ref,
               GITHUB_TOKEN='test-only-registry-token', GITHUB_ACTOR='tester')
    stub(root, 'git', 'raise SystemExit(0)\n')
    stub(root, 'openssl', "print('a' * 48)\n")
    # L'audit réseau est remplacé, mais le script réel décide login et export.
    (root / 'scripts/ci/audit_registry_cache.py').write_text('pass\n')
    stub(root, 'docker', r'''import json, os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\n')
if args[:2] == ['buildx', 'build']:
    if args[-1].endswith('pipctx'):
        print('Using cached dependency')
    elif '--secret' in args:
        print('Build secret package_token must not be empty')
        sys.exit(1)
    else:
        print('secret package_token: not found')
        sys.exit(1)
elif args[:2] == ['buildx', 'bake']:
    if any('cache-to=type=local' in arg for arg in args):
        blobs = Path('dist/layer-cache/blobs/sha256')
        blobs.mkdir(parents=True, exist_ok=True)
        (blobs / 'abc').write_text('clean cache')
    print('CACHED')
elif args[0] == 'save':
    shutil.copyfile(Path(os.environ['TEST_ROOT']) / 'fixture.tar',
                    args[args.index('--output') + 1])
''')
    result = execute(root, env, 'build_variant.sh')
    assert result.returncode == 0, result.stderr
    recorded = calls(root)
    logins = [call for call in recorded if call[:1] == ['login']]
    exports = [call for call in recorded
               if any('cache-to=type=registry' in arg for arg in call)]
    assert len(logins) == int(allowed)
    assert len(exports) == int(allowed)
    assert env['GITHUB_TOKEN'].encode() not in result.stdout + result.stderr
