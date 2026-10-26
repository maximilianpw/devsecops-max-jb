"""Chemins d'échec et de reprise des scripts TP2, avec outils simulés."""

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
CI = ROOT / 'scripts' / 'ci'
TOKEN = 'TP2_' + 'c' * 48

_spec = importlib.util.spec_from_file_location('image_archive', CI / 'image_archive.py')
images = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(images)


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def stub(directory, name, body):
    path = directory / name
    path.write_text('#!/bin/sh\n' + body)
    path.chmod(0o755)


def env_with(tmp_path, bin_dir, **extra):
    (tmp_path / 'tmp').mkdir(exist_ok=True)
    env = dict(os.environ, PATH=f'{bin_dir}{os.pathsep}{os.environ["PATH"]}',
               TMPDIR=str(tmp_path / 'tmp'), CALLS=str(tmp_path / 'calls.log'))
    env.update(extra)
    return env


def calls(tmp_path):
    path = tmp_path / 'calls.log'
    return path.read_text() if path.exists() else ''


# --- Tentative du producteur (relance des seuls jobs échoués) ---------------

def run_verify(artifact_dir, **attempts):
    metadata = json.loads((artifact_dir / 'metadata.json').read_text())
    env = dict(os.environ, EXPECTED_IMAGE_ID=metadata['image_id'],
               EXPECTED_SHA256=metadata['archive_sha256'],
               EXPECTED_PLATFORM=metadata['platform'], GITHUB_SHA=metadata['commit'],
               GITHUB_RUN_ID=metadata['run_id'], **attempts)
    return subprocess.run(
        [sys.executable, CI / 'image_archive.py', 'verify', artifact_dir],
        env=env, capture_output=True, text=True,
    )


@pytest.fixture
def artifact(tmp_path):
    layer = tar_bytes({'app': b'hello'})
    config = json.dumps({
        'os': 'linux', 'architecture': 'arm64',
        'rootfs': {'type': 'layers', 'diff_ids': [images.digest(layer)]},
    }).encode()
    archive = tar_bytes({
        'manifest.json': json.dumps(
            [{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
        'config.json': config, 'layer.tar': layer,
    })
    (tmp_path / 'image.tar').write_bytes(archive)
    (tmp_path / 'metadata.json').write_text(json.dumps({
        'image_id': images.digest(config), 'platform': 'linux/arm64',
        'archive_sha256': hashlib.sha256(archive).hexdigest(),
        'commit': 'a' * 40, 'run_id': '123', 'run_attempt': '1',
    }))
    return tmp_path


def test_rerun_consumer_accepts_producer_attempt(artifact):
    result = run_verify(artifact, GITHUB_RUN_ATTEMPT='2', EXPECTED_RUN_ATTEMPT='1')
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('attempts', [
    {'GITHUB_RUN_ATTEMPT': '2', 'EXPECTED_RUN_ATTEMPT': '2'},  # attente permutée
    {'GITHUB_RUN_ATTEMPT': '1', 'EXPECTED_RUN_ATTEMPT': '2'},  # tentative future
    {'GITHUB_RUN_ATTEMPT': '2', 'EXPECTED_RUN_ATTEMPT': '0'},
    {'GITHUB_RUN_ATTEMPT': '2', 'EXPECTED_RUN_ATTEMPT': 'x'},
    {'GITHUB_RUN_ATTEMPT': '2'},  # liaison à la tentative jamais supprimée
])
def test_producer_attempt_still_bound(artifact, attempts):
    assert run_verify(artifact, **attempts).returncode != 0


# --- test_variant.sh : nettoyage même si le diagnostic échoue ---------------

def test_failed_diagnostic_does_not_skip_teardown(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stub(bin_dir, 'docker', '''echo "$*" >> "$CALLS"
case "$*" in *" up "*|*" logs "*) exit 1 ;; esac
''')
    result = subprocess.run(
        ['bash', CI / 'test_variant.sh'], cwd=ROOT, capture_output=True, text=True,
        env=env_with(tmp_path, bin_dir, IMAGE='flask-api:test',
                     EXPECTED_PLATFORM='linux/arm64'),
    )
    assert result.returncode != 0
    assert ' logs ' in calls(tmp_path)
    assert 'down --volumes --remove-orphans' in calls(tmp_path)
    assert list((tmp_path / 'tmp').iterdir()) == []  # db_password supprimé


# --- scan_variant.sh : un gate rouge ne masque pas les autres ---------------

def scan_workspace(tmp_path):
    workspace = tmp_path / 'repo'
    (workspace / 'scripts' / 'ci').mkdir(parents=True)
    shutil.copy(CI / 'scan_variant.sh', workspace / 'scripts' / 'ci')
    stub(workspace / 'scripts' / 'ci', 'load_verified_image.sh', 'exit 0\n')
    (workspace / 'scripts' / 'ci' / 'trivy-secret.yaml').write_text('rules: []\n')
    (workspace / 'dist').mkdir()
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stub(bin_dir, 'docker', 'echo \'{"services": {"db": {"image": "db@sha256:x"}}}\'\n')
    stub(bin_dir, 'dive', 'echo "dive $*" >> "$CALLS"\n')
    # Fixture fuyant détecté ; gate vulnérabilités de l'API rouge ; le reste vert.
    stub(bin_dir, 'trivy', '''echo "trivy $*" >> "$CALLS"
out=""; prev=""
for a in "$@"; do [ "$prev" = --output ] && out=$a; prev=$a; done
case "$*" in
  "fs --scanners secret"*)
    echo '{"Results":[{"Secrets":[{"RuleID":"tp2-build-token"}]}]}' > "$out"; exit 1 ;;
  *"--input dist/image.tar --scanners vuln --skip-db-update --severity"*) exit 1 ;;
esac
[ -n "$out" ] && echo '{}' > "$out"
exit 0
''')
    return workspace, bin_dir


def test_red_api_gate_still_runs_every_report_and_gate(tmp_path):
    workspace, bin_dir = scan_workspace(tmp_path)
    result = subprocess.run(
        ['bash', 'scripts/ci/scan_variant.sh'], cwd=workspace,
        capture_output=True, text=True,
        env=env_with(tmp_path, bin_dir, IMAGE='flask-api:test',
                     EXPECTED_PLATFORM='linux/arm64'),
    )
    assert result.returncode == 1
    assert 'trivy-image' in result.stderr and 'trivy-deps' not in result.stderr
    log = calls(tmp_path)
    assert '--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .' in log
    assert ('--image-src remote --platform linux/arm64 --scanners vuln '
            '--skip-db-update --severity') in log
    for name in ['image', 'deps', 'db']:
        assert (workspace / 'reports' / f'trivy-{name}-full.json').exists()


# --- build_variant.sh : rien de fuyant parmi les artefacts publiables -------

def build_workspace(tmp_path, docker_body):
    workspace = tmp_path / 'repo'
    (workspace / 'scripts' / 'ci').mkdir(parents=True)
    for name in ['build_variant.sh', 'audit_secret.py']:
        shutil.copy(CI / name, workspace / 'scripts' / 'ci')
    (workspace / '.gitignore').write_text('secrets/\n')
    shutil.copy(ROOT / '.dockerignore', workspace)
    subprocess.run(['git', 'init', '-q'], cwd=workspace, check=True)
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    stub(bin_dir, 'docker', 'echo "$*" >> "$CALLS"\n' + docker_body)
    return workspace, bin_dir


def run_build(tmp_path, docker_body):
    workspace, bin_dir = build_workspace(tmp_path, docker_body)
    result = subprocess.run(
        ['bash', 'scripts/ci/build_variant.sh'], cwd=workspace,
        capture_output=True, text=True,
        env=env_with(tmp_path, bin_dir, ARCH='arm64', GITHUB_SHA='a' * 40,
                     GITHUB_RUN_ID='1', GITHUB_RUN_ATTEMPT='1',
                     GITHUB_OUTPUT=str(tmp_path / 'out')),
    )
    published = {p.name: p.read_bytes() for p in (workspace / 'reports').iterdir()}
    return result, published


def test_leaky_log_withheld_and_failure_before_audit(tmp_path):
    # Un log imprime le jeton, puis le build échoue avant l'audit en ligne.
    result, published = run_build(tmp_path, '''case "$*" in
  "buildx inspect"*) cat "$BUILD_SECRET_FILE" ;;
  *"--no-cache ."*) echo boom; exit 1 ;;
  "buildx build --progress=plain"*) echo "not found"; exit 1 ;;
esac
exit 0
''')
    assert result.returncode != 0
    assert 'buildkit-version.txt.withheld' in published
    assert 'buildkit-version.txt' not in published
    assert 'absent.log' in published  # diagnostic sûr conservé
    assert not any(b'TP2_' in data for data in published.values())
    assert TOKEN not in result.stdout + result.stderr
    assert list((tmp_path / 'tmp').iterdir()) == []  # jeton et logs bruts détruits


def test_clean_failure_publishes_audited_diagnostics(tmp_path):
    result, published = run_build(tmp_path, '''case "$*" in
  *"--no-cache ."*) echo boom; exit 1 ;;
  "buildx build --progress=plain"*) echo "not found"; exit 1 ;;
esac
exit 0
''')
    assert result.returncode != 0
    assert {'buildkit-version.txt', 'context.log', 'absent.log'} <= set(published)
    assert not any(name.endswith('.withheld') for name in published)
