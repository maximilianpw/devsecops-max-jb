"""Exercise CI shell entrypoints with failing tools, without Docker or a registry."""

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
    assert (result.returncode == 0) == (failure == 'none'), result.stderr
    reports = ('trivy-image-full.json', 'trivy-deps-full.json', 'trivy-db-full.json')
    for report in reports:
        assert any('reports/' + report in call for call in recorded)
    assert any(call[0] == 'fs' and 'vuln' in call and '--exit-code' in call
               for call in recorded)
    assert any('--image-src' in call and '--exit-code' in call for call in recorded)
    assert ['sbom:reports/sbom/sbom.cdx.json', '--config', '.grype.yaml'] in recorded
    assert any('--only-fixed=false' in call for call in recorded)


def make_image(path):
    # Empty image is sufficient for the real image_archive.describe boundary.
    config = json.dumps({'os': 'linux', 'architecture': 'arm64',
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
