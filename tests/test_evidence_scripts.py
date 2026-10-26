"""Evidence CLI routing, historical replay isolation and repeated TP2 builds."""

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


def executable(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!{sys.executable}\n' + source)
    path.chmod(0o755)


@pytest.fixture
def workspace(tmp_path):
    shutil.copytree(ROOT / 'scripts/evidence', tmp_path / 'scripts/evidence')
    (tmp_path / 'docker-bake.hcl').touch()
    (tmp_path / 'bin').mkdir()
    (tmp_path / 'tmp').mkdir()
    executable(tmp_path / 'bin/docker', "print('fixture tool')\n")
    executable(tmp_path / 'bin/git', '''import os, sys
from pathlib import Path
if sys.argv[1] == 'archive':
    sys.stdout.buffer.write(Path(os.environ['ARCHIVE']).read_bytes())
else:
    print('fixture revision')
''')
    env = dict(os.environ, PATH=str(tmp_path / 'bin') + ':' + os.environ['PATH'],
               TMPDIR=str(tmp_path / 'tmp'), ARCH='arm64', GITHUB_SHA='a' * 40,
               GITHUB_RUN_ID='evidence-test', GITHUB_RUN_ATTEMPT='1',
               ARCHIVE=str(tmp_path / 'historical.tar'))
    return tmp_path, env


def regenerate(root, env, *steps):
    return subprocess.run(['bash', 'scripts/evidence/regenerate.sh', *steps],
                          cwd=root, env=env, capture_output=True, text=True,
                          timeout=30)


@pytest.mark.parametrize('steps', [('all',), ('dive-db',), ('--tp1', 'run')])
@pytest.mark.parametrize('exit_code', [0, 7])
def test_tp1_replay_preserves_current_evidence(workspace, steps, exit_code):
    root, env = workspace
    script = ('#!/bin/sh\nprintf "%s\\n" "$*" > evidence/after/selected.txt\n'
              f'exit {exit_code}\n').encode()
    with tarfile.open(env['ARCHIVE'], 'w') as archive:
        files = {'scripts/evidence/regenerate.sh': script,
                 'evidence/after/stale.txt': b'historical report'}
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(data))
    current = root / 'evidence/after/current.txt'
    current.parent.mkdir(parents=True)
    current.write_text('preserve me')
    for _ in range(2):
        result = regenerate(root, env, *steps)
        assert result.returncode == exit_code, result.stderr
    reports = list((root / 'evidence/tp1').glob('*/selected.txt'))
    assert len(reports) == 2
    expected = 'run' if steps[0] == '--tp1' else steps[0]
    assert all(path.read_text().strip() == expected for path in reports)
    assert not list((root / 'evidence/tp1').glob('*/stale.txt'))
    assert current.read_text() == 'preserve me'
    assert list((root / 'tmp').iterdir()) == []


@pytest.mark.parametrize('steps', [(), ('build', 'run', 'scan'), ('run',), ('scan',)])
def test_tp2_steps_still_delegate(workspace, steps):
    root, env = workspace
    executable(root / 'scripts/evidence/tp2.sh', '''import json, sys
print(json.dumps(sys.argv[1:]))
''')
    result = regenerate(root, env, *steps)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == list(steps)


def test_repeated_build_replaces_outputs_but_consumers_keep_them(workspace):
    root, env = workspace
    executable(root / 'scripts/ci/build_variant.sh', '''import os
from pathlib import Path
with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
    out.write('image=flask-api:' + os.environ['GENERATION'] + '\\n')
    out.write('image_id=sha256:test\\narchive_sha256=test\\nrun_attempt=1\\n')
Path('dist').mkdir(exist_ok=True)
Path('dist/metadata.json').write_text('{}')
Path('reports').mkdir(exist_ok=True)
Path('reports/build.log').write_text('safe diagnostic')
''')
    for script in ('test_variant.sh', 'scan_variant.sh'):
        executable(root / 'scripts/ci' / script, '''import os
assert os.environ['IMAGE'] == 'flask-api:2'
''')
    for generation in ('1', '2'):
        result = regenerate(root, dict(env, GENERATION=generation), 'build')
        assert result.returncode == 0, result.stderr
    output = root / 'evidence/tp2/evidence-test-arm64/outputs.txt'
    contents = output.read_text()
    assert contents.count('image=') == 1
    assert 'image=flask-api:2\n' in contents
    result = regenerate(root, env, 'run', 'scan')
    assert result.returncode == 0, result.stderr
    assert output.read_text() == contents
