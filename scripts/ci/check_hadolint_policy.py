#!/usr/bin/env python3
"""Vérifie que la politique Hadolint de l'équipe (.hadolint.yaml) est appliquée.

Hadolint ignore sans prévenir une clé ou un code de règle mal orthographié :
une règle d'équipe peut donc disparaître sans que le lint du Dockerfile échoue.
Ce script vérifie que :

- `.hadolint.yaml` respecte un format strict (toute ligne non reconnue, code
  mal formé ou valeur entre guillemets est refusé) et les invariants de la
  politique : seuil `style`, `ignored: []`, pragmas désactivés, `cgr.dev`
  seul registre autorisé, seules des règles forcées en `error` ;
- les règles forcées en `error` sont exactement celles testées ici ;
- le Dockerfile du dépôt ne produit aucune alerte ;
- chaque règle d'équipe, rejouée sur un Dockerfile qui ne viole qu'elle,
  remonte en `error` et fait échouer Hadolint ;
- une alerte de niveau `style` (DL3048, hors règles d'équipe) fait échouer
  Hadolint : le seuil `failure-threshold: style` est effectif ;
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
    "49fd266eb8a1331194c318b742087c7a2939cc5794fa64f17feb9e17e12703e2"
)

# Règle -> Dockerfile qui ne viole que cette règle.
CASES = {
    # R1 - Images de base
    "DL3006": "FROM cgr.dev/chainguard/python\nUSER 65532\n",
    "DL3007": "FROM cgr.dev/chainguard/python:latest\nUSER 65532\n",
    "DL3026": "FROM quay.io/fedora/python-311:1\nUSER 65532\n",
    # R2 - Exécution sans privilèges
    "DL3002": f"{BASE}\nUSER 0\n",
    "DL3004": f"{BASE}\nRUN sudo true\nUSER 65532\n",
    # R3 - Shell robuste
    "DL4006": f"{BASE}\nRUN curl -s https://example.com | python\nUSER 65532\n",
    "SC2086": f"{BASE}\nRUN echo $HOME\nUSER 65532\n",
    "DL3003": f"{BASE}\nRUN cd /tmp && true\nUSER 65532\n",
    "DL4001": (
        f"{BASE}\nRUN wget -q https://example.com/a"
        " && curl -fsSO https://example.com/b\nUSER 65532\n"
    ),
    # R4 - Copie maîtrisée
    "DL3020": f"{BASE}\nADD app.py /app/app.py\nUSER 65532\n",
    "DL3021": f"{BASE}\nCOPY a b /app\nUSER 65532\n",
    "DL3022": f"{BASE}\nCOPY --from=cgr.dev/nope /a /a\nUSER 65532\n",
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

# Seuil : DL3048 (clé de label invalide) est de niveau style et doit bloquer.
STYLE_CASE = f'{BASE}\nLABEL Bad_key="v"\nUSER 65532\n'

# Un pragma d'exclusion ne doit rien neutraliser (disable-ignore-pragma).
PRAGMA_CASE = f"{BASE}\n# hadolint ignore=DL3020\nADD app.py /app/app.py\nUSER 65532\n"

# Valeurs attendues des clés scalaires et listes de .hadolint.yaml.
EXPECTED = {
    "failure-threshold": "style",
    "ignored": [],
    "disable-ignore-pragma": "true",
    "trustedRegistries": ["cgr.dev"],
}
CODE_RE = re.compile(r"^(?:DL|SC)\d{4}$")
TOP_RE = re.compile(r"^([A-Za-z-]+):(?: (\S+))?$")
SUB_RE = re.compile(r"^  ([A-Za-z-]+):$")
ITEM_RE = re.compile(r"^( {2}| {4})- (\S+)$")


def read_config(path):
    """Lit .hadolint.yaml dans un format strict ; renvoie (config, erreurs).

    Format accepté : `clé: valeur`, `clé:` suivie d'éléments `  - valeur`, et
    `override:` suivie de `  niveau:` puis `    - CODE`. Commentaires permis.
    """
    config, errors, key, sub = {}, [], None, None
    for number, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = re.sub(r"\s+#.*$", "", raw).rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        where = f"{path}:{number}"
        if match := TOP_RE.match(line):
            key, value, sub = match.group(1), match.group(2), None
            if key in config:
                errors.append(f"{where}: clé {key} dupliquée")
            config[key] = ([] if value == "[]" else value) if value else None
        elif (match := SUB_RE.match(line)) and key == "override":
            sub = match.group(1)
            config["override"] = config["override"] or {}
            if sub in config["override"]:
                errors.append(f"{where}: override.{sub} dupliquée")
            config["override"][sub] = []
        elif match := ITEM_RE.match(line):
            nested, item = len(match.group(1)) == 4, match.group(2)
            if key == "override" and nested and sub:
                config["override"][sub].append(item)
            elif key and not nested and key != "override" and config[key] is None:
                config[key] = [item]
            elif key and not nested and isinstance(config[key], list):
                config[key].append(item)
            else:
                errors.append(f"{where}: élément hors liste : {raw.strip()}")
        else:
            errors.append(f"{where}: ligne non reconnue : {raw.strip()}")
    return config, errors


def check_config(path):
    """Vérifie les invariants de la politique ; renvoie les erreurs."""
    config, errors = read_config(path)
    override = config.pop("override", None) or {}
    for key in sorted(config.keys() - EXPECTED.keys()):
        errors.append(f"{path}: clé inattendue : {key}")
    for key, expected in EXPECTED.items():
        if config.get(key) != expected:
            value = config.get(key)
            errors.append(f"{path}: {key} vaut {value!r}, attendu {expected!r}")
    for level in sorted(override.keys() - {"error"}):
        errors.append(f"{path}: override.{level} interdit (règles d'équipe en error)")
    declared = override.get("error", [])
    for code in declared:
        if not CODE_RE.match(code):
            errors.append(f"{path}: code invalide dans override.error : {code}")
    for code in sorted({c for c in declared if declared.count(c) > 1}):
        errors.append(f"{path}: {code} dupliquée dans override.error")
    declared = set(declared)
    for code in sorted(declared - CASES.keys()):
        errors.append(f"{code} forcée en error dans {path} mais non testée")
    for code in sorted(CASES.keys() - declared):
        errors.append(f"{code} testée mais absente de override.error ({path})")
    return errors


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
    """Exige un échec de Hadolint avec pour seule alerte `code` au niveau `level`."""
    path = Path(workdir) / name
    path.write_text(content)
    returncode, findings = hadolint(config, path)
    found = sorted((f["code"], f["level"]) for f in findings)
    if returncode == 0:
        return [f"{name} : Hadolint n'a pas échoué (attendu : {code} en {level})"]
    if found != [(code, level)]:
        listed = ", ".join(f"{c}/{lv}" for c, lv in found) or "aucune"
        return [f"{name} : seule {code}/{level} attendue, alertes obtenues : {listed}"]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default=".hadolint.yaml")
    parser.add_argument("--dockerfile", default="Dockerfile")
    args = parser.parse_args()
    config = Path(args.config).resolve()

    errors = check_config(args.config)

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
        errors += check_case(config, workdir, "seuil", STYLE_CASE, "DL3048", "style")
        errors += check_case(config, workdir, "pragma", PRAGMA_CASE, "DL3020")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"Politique Hadolint OK : configuration conforme ; {args.dockerfile} sans "
        f"alerte ; {len(CASES)} règles d'équipe bloquantes en error ; seuil style "
        "effectif ; pragma ignore sans effet."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
