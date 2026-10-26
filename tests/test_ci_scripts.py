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
        f"# escape=`\n{BASE}\nRUN echo `\n  b\n{ADD_URL}\n",
        f"{BASE}\nRUN <<-EOT sh\n\techo ok\n\tEOT\n{ADD_URL}\n",
        f"{BASE}\nADD a \\\n",
    ],
    ids=[
        "simple",
        "tabulation",
        "commentaire-antislash",
        "commentaire-dans-continuation",
        "onbuild-minuscules",
        "directive-escape",
        "apres-heredoc",
        "continuation-en-fin-de-fichier",
    ],
)
def test_add_refuse(tmp_path, content):
    errors = dockerfile_errors(tmp_path, content)
    assert len(errors) == 1 and errors[0].startswith("ADD interdit")


@pytest.mark.parametrize("quote", ["", "'", '"'])
def test_heredoc_n_est_pas_une_instruction(tmp_path, quote):
    content = (
        f"{BASE}\nRUN cat <<{quote}EOF{quote} > /tmp/x\n"
        "ADD texte\nFROM python:latest\nEOF\nUSER 65532\n"
    )
    assert dockerfile_errors(tmp_path, content) == []


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


@pytest.mark.skipif(shutil.which("hadolint") is None, reason="Hadolint absent")
def test_alerte_en_double_refusee(tmp_path):
    content = f"{BASE}\nWORKDIR foo\nWORKDIR bar\nUSER 65532\n"
    config = ROOT / ".hadolint.yaml"
    assert policy.check_case(config, tmp_path, "double", content, "DL3000")
