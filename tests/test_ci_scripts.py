"""Tests unitaires des contrôles de CI (scripts/ci), sans Docker.

Chaque contournement trouvé en revue est conservé comme cas de non-régression.
Les cas qui exécutent Hadolint sont ignorés s'il n'est pas installé.
"""

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    path = ROOT / "scripts" / "ci" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pinning = load("check_pinning")
policy = load("check_hadolint_policy")

BASE = policy.BASE
ADD_URL = "ADD https://example.com/app.tar.gz /app/"


def dockerfile_errors(tmp_path, content):
    path = tmp_path / "Dockerfile"
    path.write_text(content)
    return [error.split(": ", 1)[1] for error in pinning.check_dockerfile(path)]


def test_dockerfile_du_depot_conforme():
    assert pinning.check_dockerfile(ROOT / "Dockerfile") == []


@pytest.mark.parametrize(
    "content",
    [
        f"{BASE}\n{ADD_URL}\n",
        f"{BASE}\nADD\thttps://example.com/app.tar.gz /app/\n",
        f"{BASE}\n# commentaire \\\n{ADD_URL}\n",
        f"{BASE}\nRUN echo a \\\n# commentaire\n  b\n{ADD_URL}\n",
        f"{BASE}\nonbuild add a /b\n",
        f"{BASE}\nRUN <<-EOT sh\n\techo ok\n\tEOT\n{ADD_URL}\n",
        f"{BASE}\nADD a \\\n",
        f"FROM scratch AS u\nRUN echo '<<EOF'\n{BASE}\n{ADD_URL}\n",
        f'FROM scratch AS u\nRUN ["echo", "<<EOF"]\n{BASE}\n{ADD_URL}\n',
        f"{BASE}\nCOPY <<EOF-X /x\ntexte\nEOF-X\n\n{ADD_URL}\n",
        f"{BASE}\nRUN cat 0<<EOF\ntexte\nEOF\n{ADD_URL}\n",
        f"{BASE}\nRUN echo a<<EOF\n{ADD_URL}\n",
        f"{BASE}\nA\\\nDD https://example.com/app.tar.gz /app/\n",
        f"{BASE}\nCOPY <<'' /x\n{ADD_URL}\n\nUSER 65532\n",
    ],
    ids=[
        "simple",
        "tabulation",
        "commentaire-antislash",
        "commentaire-dans-continuation",
        "onbuild-minuscules",
        "apres-heredoc",
        "continuation-en-fin-de-fichier",
        "faux-heredoc-entre-guillemets",
        "faux-heredoc-forme-json",
        "delimiteur-complet",
        "heredoc-avec-descripteur",
        "faux-heredoc-colle-a-un-mot",
        "mot-cle-coupe-par-continuation",
        "heredoc-nom-vide",
    ],
)
def test_add_refuse(tmp_path, content):
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and errors[0].startswith("ADD interdit")


@pytest.mark.parametrize(
    "opening, name",
    [
        ("RUN cat <<EOF > /tmp/x", "EOF"),
        ("RUN cat <<'EOF' > /tmp/x", "EOF"),
        ('RUN cat <<"EOF" > /tmp/x', "EOF"),
        ("COPY <<123 /x", "123"),
        ("COPY <<'EOF-X' /x", "EOF-X"),
        ("COPY <<-EOF /x", "\tEOF"),
    ],
)
def test_heredoc_n_est_pas_une_instruction(tmp_path, opening, name):
    content = (
        f"{BASE}\n{opening}\nADD texte /y\nFROM python:latest\n{name}\n\n"
        "USER 65532\n"
    )
    assert dockerfile_errors(tmp_path, content) == []


@pytest.mark.parametrize(
    "content, reason",
    [
        (f"{BASE}\nLABEL path=C:\\\\\n{ADD_URL}\n", "échappement final ambigu"),
        (f"{BASE}\nLABEL p=\\\\\\\n{ADD_URL}\n", "échappement final ambigu"),
        (f"# escape=`\n{BASE}\nLABEL n=v`\n{ADD_URL}\n", "directive de parseur"),
        (f"  # escape=`\n{BASE}\n", "directive de parseur interdite"),
        (f"# commentaire\n\n# escape=`\n{BASE}\n", "directive de parseur"),
        (f"# anything=x\n# escape=`\n{BASE}\n", "directive de parseur interdite"),
        (f"# syntax=docker/dockerfile:1\n{BASE}\n", "directive de parseur interdite"),
        (f'{BASE}\nCOPY <<"E\\OF" /x\nE\\OF\n', "délimiteur de heredoc non supporté"),
        (f"{BASE}\nRUN cat <<CMD ${{#v}}\n{ADD_URL}\nCMD\n", "ouverture de heredoc"),
        (f"{BASE}\nRUN cat <<CMD ${{v^^}}\n{ADD_URL}\nCMD\n", "ouverture de heredoc"),
        (f"{BASE}\nRUN cat <<CMD 'abc\n{ADD_URL}\nCMD\n", "ouverture de heredoc"),
        (f"{BASE}\nRUN cat <<CMD $v\n{ADD_URL}\nCMD\n", "ouverture de heredoc"),
    ],
    ids=[
        "double-antislash",
        "triple-antislash",
        "directive-escape",
        "directive-indentee",
        "directive-apres-ligne-vide",
        "directive-apres-directive-inconnue",
        "directive-syntax",
        "delimiteur-avec-echappement",
        "heredoc-expansion-longueur",
        "heredoc-expansion-majuscules",
        "heredoc-guillemet-non-ferme",
        "heredoc-variable",
    ],
)
def test_syntaxe_ambigue_refusee(tmp_path, content, reason):
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and reason in errors[0]


@pytest.mark.parametrize(
    "separator",
    ["\v", "\f", "\r", "\x1e", "\x85", "\u2028", "\u2029"],
    ids=["vt", "ff", "cr", "us", "nel", "ls", "ps"],
)
def test_separateur_de_ligne_non_lf_refuse(tmp_path, separator):
    content = f"{BASE}\nLABEL a=b{separator}COPY <<EOF /x{separator}\n{ADD_URL}\nEOF\n"
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and "non autorisé" in errors[0]


@pytest.mark.parametrize("space", ["\u00a0", "\u2003", "\u2009"])
def test_espace_unicode_apres_continuation_refuse(tmp_path, space):
    content = f"{BASE}\nLABEL p=a\\{space}\n{ADD_URL}\n"
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and "non autorisé" in errors[0]


def test_crlf_refuse_meme_lu_en_texte(tmp_path):
    path = tmp_path / "Dockerfile"
    path.write_bytes(f"{BASE}\r\nUSER 65532\r\n".encode())
    errors = [e.split(": ", 1)[1] for e in pinning.check_dockerfile(path)]
    assert len(errors) == 1 and "U+000D" in errors[0]


def test_accents_des_commentaires_acceptes(tmp_path):
    assert dockerfile_errors(tmp_path, f"# image — publiée le 26\n{BASE}\n") == []


def test_heredoc_non_termine_refuse(tmp_path):
    errors = dockerfile_errors(tmp_path, f"{BASE}\nCOPY <<EOF /x\n{ADD_URL}\n")
    assert len(errors) == 1 and "heredoc 'EOF' non terminé" in errors[0]


def test_bom_ne_masque_pas_from(tmp_path):
    content = "\ufeffFROM cgr.dev/chainguard/python:latest-dev AS mutable\n"
    assert dockerfile_errors(tmp_path, content) == [
        "image non épinglée par digest : cgr.dev/chainguard/python:latest-dev"
    ]


def test_from_masque_par_commentaire_detecte(tmp_path):
    errors = dockerfile_errors(tmp_path, "# commentaire \\\nFROM python:latest\n")
    assert errors == ["image non épinglée par digest : python:latest"]


def test_requirements_du_depot_conformes():
    paths = [ROOT / "requirements.txt", ROOT / "requirements-dev.txt"]
    assert pinning.check_requirements(paths) == []


@pytest.mark.parametrize(
    "line",
    ["Flask>=3", "flask", "-r requirements.txt", "Flask==3.*; python_version>'3'"],
)
def test_requirement_non_epingle_refuse(tmp_path, line):
    path = tmp_path / "requirements.txt"
    path.write_text(f"# commentaire\nWerkzeug==3.1.9\n{line}\n")
    assert len(pinning.check_requirements([path])) == 1


def test_politique_hadolint_du_depot_conforme():
    assert policy.check_config(ROOT / ".hadolint.yaml") == []


# Mutations de .hadolint.yaml : chacune doit être signalée.
MUTATIONS = {
    "regle-retiree": ("    - DL3025  # CMD / ENTRYPOINT en forme shell\n", ""),
    "code-mal-saisi": ("DL3042", "DL3O42"),
    "pragmas-autorises": ("pragma: true", "pragma: false"),
    "cle-mal-saisie": ("disable-ignore-pragma:", "disable-ignore-pragmas:"),
    "seuil-releve": ("failure-threshold: style", "failure-threshold: info"),
    "ignored-en-ligne": ("ignored: []", "ignored: [DL3008]"),
    "ignored-liste": ("ignored: []", "ignored:\n  - DL3008"),
    "registre-ajoute": ("  - cgr.dev\n", "  - cgr.dev\n  - docker.io\n"),
    "override-warning": ("override:\n", "override:\n  warning:\n    - DL3008\n"),
}
APPENDS = {
    "regle-entre-guillemets": "    - 'DL3008'\n",
    "regle-sans-test": "    - DL3008\n",
    "cle-dupliquee": "ignored: []\n",
    "sous-cle-dupliquee": "  error:\n",
}


@pytest.mark.parametrize("name", [*MUTATIONS, *APPENDS])
def test_mutation_politique_detectee(tmp_path, name):
    text = (ROOT / ".hadolint.yaml").read_text()
    if name in MUTATIONS:
        old, new = MUTATIONS[name]
        assert old in text
        text = text.replace(old, new, 1)
    else:
        text += APPENDS[name]
    path = tmp_path / ".hadolint.yaml"
    path.write_text(text)
    assert policy.check_config(path)


def test_alerte_en_double_refusee_sans_hadolint(tmp_path, monkeypatch):
    finding = {"code": "DL3000", "level": "error", "line": 2, "message": "m"}
    monkeypatch.setattr(policy, "hadolint", lambda config, path: (1, [finding] * 2))
    assert policy.check_case(ROOT / ".hadolint.yaml", tmp_path, "double", "", "DL3000")


@pytest.mark.skipif(shutil.which("hadolint") is None, reason="Hadolint absent")
def test_alerte_en_double_refusee(tmp_path):
    content = f"{BASE}\nWORKDIR foo\nWORKDIR bar\nUSER 65532\n"
    config = ROOT / ".hadolint.yaml"
    assert policy.check_case(config, tmp_path, "double", content, "DL3000")


def test_descripteur_unicode_ne_masque_pas_add(tmp_path):
    content = (
        "FROM scratch AS u\nRUN cat ١<<EOF\nFROM scratch\n"
        "ADD payload.tar.gz /x/\nLABEL p=\\\nEOF\n\nUSER 65532\n"
    )
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and errors[0].startswith("ADD interdit")


@pytest.mark.parametrize("instruction", ["ARG", "ONBUILD ARG"])
def test_arg_differe_ou_local_ne_modifie_pas_from(tmp_path, instruction):
    digest = "a" * 64
    content = (
        "ARG TAG=latest-dev\nFROM scratch AS builder\n"
        f"{instruction} TAG=latest-dev@sha256:{digest}\n"
        "FROM cgr.dev/chainguard/python:${TAG}\nUSER 65532\n"
    )
    assert dockerfile_errors(tmp_path, content) == [
        "image non épinglée par digest : cgr.dev/chainguard/python:latest-dev"
    ]


FRONTEND = (
    '# syntax=docker/dockerfile:1@sha256:'
    '4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e'
)
TP2_PIP = (
    f'{FRONTEND}\n{BASE}\n'
    'ENV PIP_CACHE_DIR=/home/nonroot/.cache/pip\n'
    'RUN --mount=type=cache,target=/home/nonroot/.cache/pip,'
    'uid=65532,gid=65532,sharing=locked '
    '--mount=type=secret,id=package_token,required=true,'
    'uid=65532,gid=65532,mode=0400 '
    'test -s /run/secrets/package_token && '
    'pip --python /app/venv/bin/python install -r /app/requirements.txt\n'
    'USER 65532\n'
)


def test_frontend_epingle_accepte_sans_elargir_from(tmp_path):
    assert dockerfile_errors(tmp_path, f'{FRONTEND}\n{BASE}\n') == []
    assert dockerfile_errors(tmp_path, f'{FRONTEND}\nFROM python:latest\n')


@pytest.mark.parametrize('prefix', ['\n', '# commentaire\n', FRONTEND + '\n'])
def test_frontend_hors_premiere_ligne_refuse(tmp_path, prefix):
    assert dockerfile_errors(tmp_path, prefix + FRONTEND + '\n' + BASE)


@pytest.mark.parametrize('frontend', [
    FRONTEND.replace('docker/dockerfile:1', 'evil/frontend:1'),
    FRONTEND.replace('docker/dockerfile:1', 'docker/dockerfile:1-labs'),
    FRONTEND.split('@')[0], FRONTEND + ' # commentaire',
    FRONTEND.replace('sha256:', 'sha512:'),
])
def test_frontend_hors_contrat_refuse(tmp_path, frontend):
    assert dockerfile_errors(tmp_path, frontend + '\n' + BASE)


def test_pip_cache_tp2_accepte(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text(TP2_PIP)
    assert pinning.check_dockerfile(path, require_tp2=True) == []


@pytest.mark.parametrize('old,new', [
    ('target=/home/nonroot/.cache/pip', 'target=/root/.cache/pip'),
    ('uid=65532', 'uid=0'), ('gid=65532', 'gid=0'),
    ('sharing=locked', 'sharing=shared'),
    ('required=true', 'required=false'),
    ('mode=0400', 'mode=0444'),
    ('id=package_token', 'id=other_token'),
    ('ENV PIP_CACHE_DIR=/home/nonroot/.cache/pip\n', ''),
    (' install -r', ' install --no-cache-dir -r'),
    (' install -r', ' install --cache-dir=/tmp/pip -r'),
    ('test -s', 'PIP_CACHE_DIR=/tmp pip --version && test -s'),
    ('test -s', 'ln -s /tmp /home/nonroot/.cache/pip && test -s'),
    ('type=cache', 'type=bind'),
    ('sharing=locked', 'sharing=locked,sharing=shared'),
    ('/app/requirements.txt\n', '/app/requirements.txt && echo done\n'),
])
def test_pip_cache_incorrect_refuse(tmp_path, old, new):
    assert dockerfile_errors(tmp_path, TP2_PIP.replace(old, new))


def test_cache_pip_ordinaire_refuse(tmp_path):
    assert dockerfile_errors(tmp_path, f'{BASE}\nRUN pip install flask==3.1.2\n')


def test_tp1_accepte_mais_refuse_en_mode_tp2(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text(f'{BASE}\nRUN pip install --no-cache-dir flask==3.1.2\n')
    assert pinning.check_dockerfile(path) == []
    assert pinning.check_dockerfile(path, require_tp2=True)


@pytest.mark.skipif(shutil.which('hadolint') is None, reason='Hadolint absent')
def test_hadolint_reconnait_cache_exact_du_contrat(tmp_path):
    path = tmp_path / 'Dockerfile'
    path.write_text(TP2_PIP)
    assert policy.hadolint(ROOT / '.hadolint.yaml', path) == (0, [])
