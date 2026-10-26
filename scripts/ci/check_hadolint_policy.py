#!/usr/bin/env python3
"""Vérifie que la politique Hadolint de l'équipe (.hadolint.yaml) est appliquée.

Hadolint ignore sans prévenir une clé ou un code de règle mal orthographié :
une règle d'équipe peut donc disparaître sans que le lint du Dockerfile échoue.
Ce script lance Hadolint avec la configuration du dépôt et vérifie que :

- le Dockerfile du dépôt ne produit aucune alerte ;
- chaque règle forcée en `error` dans `.hadolint.yaml` est déclenchée en
  `error` par un Dockerfile volontairement fautif, et fait échouer Hadolint ;
- chaque règle testée ici est bien déclarée dans `.hadolint.yaml` ;
- une alerte de niveau `info` (DL3059, hors règles d'équipe) fait échouer
  Hadolint : le seuil `failure-threshold: info` est effectif ;
- un commentaire `# hadolint ignore=...` ne neutralise aucune règle.

Usage :
    python3 scripts/ci/check_hadolint_policy.py [--config .hadolint.yaml]

Code retour non nul si au moins une violation est trouvée.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = (
    "FROM cgr.dev/chainguard/python@sha256:"
    "b6248c85ba9b97e1e61b30197f309cc4d21661f889fefa5268f0a7bc530dad46"
)

# Règle -> Dockerfile qui ne viole que cette règle (et USER non root final).
CASES = {
    # R1 - Images de base
    "DL3006": "FROM cgr.dev/chainguard/python\nUSER 65532\n",
    "DL3007": "FROM cgr.dev/chainguard/python:latest\nUSER 65532\n",
    "DL3026": "FROM quay.io/fedora/python-311:1\nUSER 65532\n",
    # R2 - Exécution sans privilèges
    "DL3002": f"{BASE}\nUSER root\n",
    "DL3004": f"{BASE}\nRUN sudo true\nUSER 65532\n",
    # R3 - Shell robuste
    "DL4006": f"{BASE}\nRUN curl -s https://example.com | python\nUSER 65532\n",
    "SC2086": f"{BASE}\nRUN echo $HOME\nUSER 65532\n",
    "DL3003": f"{BASE}\nRUN cd /tmp && true\nUSER 65532\n",
    "DL4001": (
        f"{BASE}\nRUN wget -q https://example.com/a\n"
        "RUN curl -fsSO https://example.com/b\nUSER 65532\n"
    ),
    # R4 - Copie maîtrisée
    "DL3020": f"{BASE}\nADD app.py /app/app.py\nUSER 65532\n",
    "DL3021": f"{BASE}\nCOPY a b /app\nUSER 65532\n",
    "DL3022": f"{BASE}\nCOPY --from=nope /a /a\nUSER 65532\n",
    "DL3045": f"{BASE}\nCOPY app.py app.py\nUSER 65532\n",
    "DL3000": f"{BASE}\nWORKDIR app\nUSER 65532\n",
    # R5 - Dépendances Python
    "DL3013": f"{BASE}\nRUN pip install --no-cache-dir flask\nUSER 65532\n",
    "DL3042": f"{BASE}\nRUN pip install flask==3.1.2\nUSER 65532\n",
    # R6 - Démarrage prévisible
    "DL3025": f"{BASE}\nUSER 65532\nCMD python app.py\n",
    "DL4003": f'{BASE}\nUSER 65532\nCMD ["a"]\nCMD ["b"]\n',
    "DL4004": f'{BASE}\nUSER 65532\nENTRYPOINT ["a"]\nENTRYPOINT ["b"]\n',
}

# Un pragma d'exclusion ne doit rien neutraliser (disable-ignore-pragma).
PRAGMA_CASE = f"{BASE}\n# hadolint ignore=DL3020\nADD app.py /app/app.py\nUSER 65532\n"

# Seuil : DL3059 (RUN consécutifs) est de niveau info par défaut et doit bloquer.
INFO_CASE = f"{BASE}\nRUN true\nRUN true\nUSER 65532\n"

RULE_RE = re.compile(r"^\s*-\s*((?:DL|SC)\d{4})\b")


def error_rules(config):
    """Codes listés sous `override: error:` (YAML lu ligne à ligne, sans PyYAML)."""
    rules, section, in_error = set(), None, False
    for line in Path(config).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            section, in_error = line.split(":", 1)[0], False
        elif section == "override" and re.match(r"^\s+\w+:", line):
            in_error = line.strip().startswith("error:")
        elif section == "override" and in_error and (match := RULE_RE.match(line)):
            rules.add(match.group(1))
    return rules


def hadolint(config, dockerfile):
    """Renvoie (code retour, alertes JSON) de Hadolint sur un fichier."""
    result = subprocess.run(
        ["hadolint", "--config", str(config), "--format", "json", str(dockerfile)],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        findings = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        sys.exit(f"Sortie Hadolint illisible :\n{result.stdout}{result.stderr}")
    return result.returncode, findings


def check_case(config, workdir, name, content, code, level="error"):
    path = Path(workdir) / name
    path.write_text(content)
    returncode, findings = hadolint(config, path)
    levels = {f["level"] for f in findings if f["code"] == code}
    if returncode == 0:
        return [f"{name} : Hadolint n'a pas échoué (attendu : {code} en {level})"]
    if levels != {level}:
        found = ", ".join(f"{f['code']}/{f['level']}" for f in findings) or "aucune"
        return [f"{name} : {code} attendu en {level}, alertes obtenues : {found}"]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default=".hadolint.yaml")
    parser.add_argument("--dockerfile", default="Dockerfile")
    args = parser.parse_args()
    config = Path(args.config).resolve()

    errors = []
    declared = error_rules(config)
    for code in sorted(declared - CASES.keys()):
        errors.append(f"{code} forcée en error dans {args.config} mais non testée")
    for code in sorted(CASES.keys() - declared):
        errors.append(f"{code} testée mais absente de override.error ({args.config})")

    returncode, findings = hadolint(config, args.dockerfile)
    if returncode != 0 or findings:
        errors += [
            f"{args.dockerfile}:{f['line']} {f['code']} {f['level']}: {f['message']}"
            for f in findings
        ]
        if not findings:
            errors.append(f"{args.dockerfile} : Hadolint a échoué ({returncode})")

    with tempfile.TemporaryDirectory() as workdir:
        for code, content in CASES.items():
            case_errors = check_case(config, workdir, code, content, code)
            errors += case_errors
            if not case_errors:
                print(f"{code}: error, bloquant")
        errors += check_case(config, workdir, "seuil", INFO_CASE, "DL3059", "info")
        errors += check_case(config, workdir, "pragma", PRAGMA_CASE, "DL3020")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"Politique Hadolint OK : {args.dockerfile} sans alerte ; "
        f"{len(CASES)} règles d'équipe bloquantes en error ; seuil info effectif ; "
        "pragma ignore sans effet."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
