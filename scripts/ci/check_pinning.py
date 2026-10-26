#!/usr/bin/env python3
"""Vérifie que les références externes sont immuables.

- Dockerfile : chaque image de base FROM est épinglée par digest sha256 ;
  aucune instruction ADD (téléchargement ou extraction sans empreinte,
  que Hadolint DL3020 tolère pour une URL ou une archive).
- Compose : chaque image externe est épinglée par digest ; PostgreSQL vient de
  Chainguard (cgr.dev/chainguard/postgres). Le service API est exempté car son
  image est celle construite par la CI (API_IMAGE).
- Compose (durcissement) : chaque service est en lecture seule, sans
  capability, sans élévation de privilèges, avec limites mémoire et PID, sans
  `env_file` (non contrôlable ici) et ne reçoit le mot de passe que comme
  secret fichier (clé contenant PASSWORD sans suffixe _FILE refusée).
- Workflows : chaque action externe est référencée par un SHA de commit complet.
- Dépendances Python (requirements*.txt) : chaque paquet est épinglé à une
  version exacte (`nom==version`), sans plage ni URL.

Usage :
    docker compose config --no-interpolate --format json \
        | python3 scripts/ci/check_pinning.py --compose-json -

Code retour non nul si au moins une violation est trouvée.
"""

import argparse
import json
import re
import shlex
import sys
import unicodedata
from pathlib import Path

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
ACTION_SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
REQUIREMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9.!+_-]+$")
# Forme d'une directive de parseur (`# escape=`, `# syntax=`...), comme BuildKit.
FRONTEND_RE = re.compile(
    r"^# syntax=docker/dockerfile:1(?:\.[0-9]+){0,2}@sha256:[0-9a-f]{64}$"
)
PIP_CACHE = "/home/nonroot/.cache/pip"
CACHE_MOUNT = {
    "type": "cache", "target": PIP_CACHE, "uid": "65532",
    "gid": "65532", "sharing": "locked",
}

DIRECTIVE_RE = re.compile(r"^#\s*[A-Za-z][A-Za-z0-9_-]*\s*=")
# Délimiteurs de heredoc acceptés : simples, éventuellement entre guillemets.
HEREDOC_NAME_RE = re.compile(r"^(['\"]?)[A-Za-z0-9_.-]+\1$")
# Seuls blancs reconnus : espace et tabulation, comme BuildKit.
BLANKS = " \t"
# Contrôle, séparateurs de ligne/paragraphe, espaces Unicode, formatage.
FORBIDDEN_CATEGORIES = {"Cc", "Zl", "Zp", "Zs", "Cf"}
HEREDOC_INSTRUCTIONS = {"RUN", "COPY", "ADD"}
# Comme BuildKit : un mot shell (guillemets conservés) de la forme [fd]<<[-]nom.
HEREDOC_RE = re.compile(r"^([0-9]*)<<(-?)([^<]*)$")
DOCKER_ACTION_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
CHAINGUARD_POSTGRES = "cgr.dev/chainguard/postgres"
API_SERVICE = "api-python"
DB_SERVICE = "db"
# Formes acceptées par Docker pour la même option.
NO_NEW_PRIVILEGES = {
    "no-new-privileges",
    "no-new-privileges:true",
    "no-new-privileges=true",
}


def instructions(text):
    """Renvoie les instructions (MOT-CLÉ, arguments) d'un Dockerfile.

    Lecture comme BuildKit : BOM initial ignoré ; ligne de commentaire retirée
    avant de résoudre les continuations (un `\\` final ne la prolonge pas) ;
    continuation concaténée sans séparateur (`A\\` puis `DD` donne `ADD`) ;
    lignes vides d'une continuation ignorées ; mot-clé séparé par tout blanc ;
    ONBUILD conservé ; heredocs reconnus seulement en forme shell de RUN, COPY
    et ADD, sur un mot shell entier `[fd]<<[-]nom`, nom vide exclu.

    Syntaxes ambiguës refusées (ValueError) plutôt qu'interprétées : directive
    de parseur hors frontend stable épinglé en première ligne, échappement final
    doublé (`\\\\`), délimiteur
    de heredoc autre qu'un nom simple, heredoc non terminé.
    """
    text = text.removeprefix("\ufeff")
    check_characters(text)
    # Découpage sur LF uniquement, comme BuildKit (splitlines() couperait aussi
    # sur \v, \f, U+2028...) ; les autres séparateurs sont refusés ci-dessus.
    lines = text.split("\n")
    # Une directive après un commentaire/ligne vide serait ignorée par BuildKit.
    # Refuser aussi les doublons dans l’en-tête.
    for index, line in enumerate(lines):
        if line.strip() and not line.lstrip().startswith("#"):
            break
        if DIRECTIVE_RE.match(line.strip()):
            if index != 0 or not FRONTEND_RE.fullmatch(line):
                raise ValueError(
                    f"directive de parseur interdite ou frontend non épinglé : {line}"
                )
    result, logical, index = [], None, 0
    while index < len(lines) or logical is not None:
        raw = lines[index] if index < len(lines) else ""
        index += 1
        stripped = raw.strip(BLANKS)
        if index <= len(lines) and (not stripped or stripped.startswith("#")):
            continue
        body = raw.rstrip(BLANKS)
        if body.endswith("\\\\"):
            raise ValueError(f"échappement final ambigu : {stripped}")
        part = body[:-1] if body.endswith("\\") else body
        logical = part.lstrip(BLANKS) if logical is None else logical + part
        if body.endswith("\\") and index < len(lines):
            continue
        instruction, index = parse_instruction(logical, lines, index)
        result.append(instruction)
        logical = None
    return result


def check_characters(text):
    """Refuse les caractères de contrôle et d'espacement autres que espace,
    tabulation et LF : Python et BuildKit ne les traitent pas de la même façon
    (fin de ligne, espace avant une continuation). CR compris (fins de ligne
    Windows refusées)."""
    for number, line in enumerate(text.split("\n"), 1):
        for char in line:
            category = unicodedata.category(char)
            if char not in BLANKS and category in FORBIDDEN_CATEGORIES:
                code = f"U+{ord(char):04X}"
                raise ValueError(f"caractère {code} non autorisé ligne {number}")


def parse_instruction(logical, lines, index):
    """Instruction logique -> ((MOT-CLÉ, arguments), index après ses heredocs)."""
    instruction = split_instruction(logical)
    keyword, args = instruction
    if keyword == "ONBUILD":
        keyword, args = split_instruction(args)
    for strip_tabs, name in heredocs(keyword, args):
        while True:
            if index >= len(lines):
                raise ValueError(f"heredoc {name!r} non terminé ({keyword} {args})")
            data = lines[index]
            index += 1
            if (data.lstrip("\t") if strip_tabs else data) == name:
                break
    return instruction, index


def shell_words(line, escape="\\"):
    """Découpe en mots shell en conservant guillemets et échappements."""
    words, word, quote, index = [], None, None, 0
    while index < len(line):
        char = line[index]
        if quote:
            word += char
            if char == escape and quote == '"' and index + 1 < len(line):
                index += 1
                word += line[index]
            elif char == quote:
                quote = None
        elif char.isspace():
            if word is not None:
                words.append(word)
            word = None
        else:
            word = (word or "") + char
            if char == escape and index + 1 < len(line):
                index += 1
                word += line[index]
            elif char in "'\"":
                quote = char
        index += 1
    if word is not None:
        words.append(word)
    return words


def unquote(word, escape="\\"):
    """Retire guillemets et échappements d'un mot shell."""
    result, quote, index = "", None, 0
    while index < len(word):
        char = word[index]
        if char == quote:
            quote = None
        elif not quote and char in "'\"":
            quote = char
        elif char == escape and quote != "'" and index + 1 < len(word):
            index += 1
            result += word[index]
        else:
            result += char
        index += 1
    return result


def heredocs(keyword, args):
    """Heredocs ouverts par une instruction : [(retrait des tabulations, nom)]."""
    if keyword not in HEREDOC_INSTRUCTIONS:
        return []
    try:
        if isinstance(json.loads(args), list):
            return []
    except ValueError:
        pass
    found = []
    for word in shell_words(args):
        match = HEREDOC_RE.match(word)
        if not match or not unquote(match.group(3)):
            continue
        if not HEREDOC_NAME_RE.match(match.group(3)):
            raise ValueError(f"délimiteur de heredoc non supporté : {word}")
        found.append((match.group(2) == "-", unquote(match.group(3))))
    # BuildKit abandonne les heredocs d'une ligne que son lexer ne sait pas
    # lire (expansion ${...} non supportée, guillemet non fermé...) : la ligne
    # d'ouverture doit donc être lexicalement simple.
    simple = not any(char in args for char in "$`\\") and quotes_balanced(args)
    if found and not simple:
        raise ValueError(
            f"ligne d'ouverture de heredoc non supportée : {keyword} {args}"
        )
    return found


def quotes_balanced(text):
    """Vrai si les guillemets simples et doubles de `text` sont tous fermés."""
    quote = None
    for char in text:
        if quote and char == quote:
            quote = None
        elif not quote and char in "'\"":
            quote = char
    return quote is None


def split_instruction(logical):
    """Sépare le mot-clé (en majuscules) de ses arguments, sur tout blanc."""
    keyword, *rest = re.split(r"\s+", logical.strip(), maxsplit=1)
    return keyword.upper(), rest[0] if rest else ""


def check_pip_cache(parsed, require_tp2=False):
    """Le cache pip doit être désactivé (TP1) ou monté selon le contrat TP2.

    Les RUN pip sont volontairement restreints à une forme shell explicite ;
    les constructions indirectes ne sont pas un contrat supporté.
    """
    errors, cache_env, mounted = [], False, 0
    for keyword, rest in parsed:
        if keyword == "FROM":
            cache_env = False
        if keyword == "ENV" and "PIP_CACHE_DIR" in rest:
            cache_env = rest.strip() == f"PIP_CACHE_DIR={PIP_CACHE}"
            if not cache_env:
                errors.append("PIP_CACHE_DIR doit être fixé au chemin du contrat")
        if keyword != "RUN" or not re.search(r"\bpip(?:3)?\b", rest):
            continue
        try:
            words = shlex.split(rest)
        except ValueError:
            errors.append("commande pip illisible")
            continue
        mounts = []
        while words and words[0].startswith("--mount="):
            fields = words.pop(0)[len("--mount="):].split(",")
            pairs = [field.partition("=") for field in fields]
            options = {key: value for key, _, value in pairs}
            if len(options) != len(pairs):
                errors.append("option de montage dupliquée")
            mounts.append(options)
        caches = [m for m in mounts if m.get("type") == "cache"]
        if not caches and not require_tp2 and "--no-cache-dir" in words:
            continue
        if caches != [CACHE_MOUNT] or not cache_env:
            errors.append("pip exige le cache BuildKit et PIP_CACHE_DIR du contrat")
        if "--no-cache-dir" in words or "PIP_NO_CACHE_DIR" in rest:
            errors.append("le chemin TP2 doit réutiliser le cache pip")
        command = "pip --python /app/venv/bin/python install -r /app/requirements.txt"
        # Pas d'override --cache-dir, de variable shell ou de commande après pip.
        commands, current = [], []
        for word in words:
            if word == "&&":
                commands.append(current)
                current = []
            else:
                current.append(word)
        commands.append(current)
        secret_check = (
            "from pathlib import Path; import sys; "
            "sys.exit(0 if Path('/run/secrets/package_token').read_bytes() "
            "else 'Build secret package_token must not be empty')"
        )
        setup = [
            ["python", "-m", "venv", "--without-pip", "/app/venv"],
            ["test", "-s", "/run/secrets/package_token"],
            ["test", "-w", "${PIP_CACHE_DIR}"],
            ["python", "-c", secret_check],
        ]
        if commands[-1] != command.split() or any(
            c not in setup for c in commands[:-1]
        ):
            errors.append("commande pip TP2 hors contrat")
        mounted += 1
    if require_tp2 and mounted != 1:
        errors.append("TP2 exige exactement une installation pip avec cache monté")
    return errors


def check_dockerfile(path, require_tp2=False):
    errors = []
    args = {}
    stages = set()
    before_first_from = True
    try:
        # Lecture en octets : read_text() convertirait \r en \n sans le dire.
        parsed = instructions(Path(path).read_bytes().decode("utf-8"))
    except ValueError as error:  # UnicodeDecodeError compris
        return [f"{path}: Dockerfile illisible : {error}"]
    errors += [f"{path}: {e}" for e in check_pip_cache(parsed, require_tp2)]
    if require_tp2 and not FRONTEND_RE.fullmatch(
        Path(path).read_text().removeprefix("\ufeff").split("\n")[0]
    ):
        errors.append(f"{path}: TP2 exige la directive frontend épinglée en tête")
    for keyword, rest in parsed:
        if keyword == "ONBUILD":
            # Un déclencheur ne modifie pas les ARG ni les étapes du build.
            trigger, trigger_args = split_instruction(rest)
            if trigger == "ADD":
                errors.append(
                    f"{path}: ADD interdit, utiliser COPY : ONBUILD ADD {trigger_args}"
                )
            continue
        if keyword == "ARG" and before_first_from:
            name, _, default = rest.strip().partition("=")
            args[name.strip()] = default.strip().strip("\"'")
            continue
        if keyword == "ADD":
            errors.append(f"{path}: ADD interdit, utiliser COPY : ADD {rest}")
            continue
        if keyword != "FROM":
            continue
        before_first_from = False
        tokens = [t for t in rest.split() if not t.startswith("--")]
        if not tokens:
            errors.append(f"{path}: FROM sans image")
            continue
        image = re.sub(
            r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1), m.group(0)), tokens[0]
        )
        if len(tokens) >= 3 and tokens[1].upper() == "AS":
            stages.add(tokens[2].lower())
        if image.lower() in stages or image == "scratch":
            continue
        if not DIGEST_RE.search(image):
            errors.append(f"{path}: image non épinglée par digest : {image}")
    return errors


def check_compose(config):
    errors = []
    services = config.get("services", {})
    for name, service in sorted(services.items()):
        image = service.get("image")
        if name == API_SERVICE:
            if not image or "API_IMAGE" not in image:
                errors.append(
                    f"compose: {API_SERVICE} doit utiliser "
                    "image: ${API_IMAGE:-flask-api:local}"
                )
            continue
        if not image:
            errors.append(f"compose: service {name} sans image explicite")
            continue
        if not DIGEST_RE.search(image):
            errors.append(f"compose: {name} non épinglé par digest : {image}")
    db_image = services.get(DB_SERVICE, {}).get("image", "")
    if not db_image.startswith(CHAINGUARD_POSTGRES):
        errors.append(
            f"compose: {DB_SERVICE} doit utiliser {CHAINGUARD_POSTGRES} : "
            f"{db_image or 'absent'}"
        )
    if services.get(DB_SERVICE, {}).get("ports"):
        errors.append(f"compose: {DB_SERVICE} ne doit publier aucun port")
    return errors


def check_hardening(config):
    errors = []
    for name, service in sorted(config.get("services", {}).items()):
        if service.get("read_only") is not True:
            errors.append(f"compose: {name} doit être read_only")
        if [c.upper() for c in service.get("cap_drop", [])] != ["ALL"]:
            errors.append(f"compose: {name} doit avoir cap_drop: [ALL]")
        if service.get("cap_add"):
            errors.append(f"compose: {name} ne doit ajouter aucune capability")
        if not NO_NEW_PRIVILEGES.intersection(service.get("security_opt", [])):
            errors.append(f"compose: {name} doit activer no-new-privileges")
        if not service.get("mem_limit") or not service.get("pids_limit"):
            errors.append(f"compose: {name} doit fixer mem_limit et pids_limit")
        if service.get("privileged"):
            errors.append(f"compose: {name} ne doit pas être privileged")
        if service.get("env_file"):
            errors.append(
                f"compose: {name} ne doit pas utiliser env_file (variables non "
                "contrôlées, risque de mot de passe en clair)"
            )
        # --no-interpolate garde la forme d'origine : liste "K=V" ou dictionnaire.
        environment = service.get("environment") or {}
        if isinstance(environment, list):
            keys = [item.split("=", 1)[0] for item in environment]
        else:
            keys = list(environment)
        if any("PASSWORD" in key and not key.endswith("_FILE") for key in keys):
            errors.append(
                f"compose: {name} reçoit un mot de passe en variable "
                "d'environnement (utiliser un secret *_FILE)"
            )
    return errors


def check_workflows(directory):
    errors = []
    uses_re = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)")
    for path in sorted(Path(directory).glob("*.y*ml")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = uses_re.match(line)
            if not match:
                continue
            ref = match.group(1)
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                ok = DOCKER_ACTION_RE.match(ref)
            else:
                ok = ACTION_SHA_RE.match(ref)
            if not ok:
                errors.append(f"{path}:{number}: action non épinglée par SHA : {ref}")
    return errors


def check_requirements(paths):
    errors = []
    for path in paths:
        for number, line in enumerate(Path(path).read_text().splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if line and not REQUIREMENT_RE.match(line):
                errors.append(f"{path}:{number}: dépendance non épinglée (==) : {line}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--require-tp2", action="store_true")
    parser.add_argument(
        "--compose-json",
        required=True,
        help="sortie de `docker compose config --no-interpolate --format json`"
        " (- pour stdin)",
    )
    parser.add_argument("--workflows", default=".github/workflows")
    parser.add_argument(
        "--requirements",
        nargs="+",
        default=["requirements.txt", "requirements-dev.txt"],
    )
    options = parser.parse_args()

    if options.compose_json == "-":
        compose = json.load(sys.stdin)
    else:
        compose = json.loads(Path(options.compose_json).read_text())

    errors = (
        check_dockerfile(options.dockerfile, options.require_tp2)
        + check_compose(compose)
        + check_hardening(compose)
        + check_workflows(options.workflows)
        + check_requirements(options.requirements)
    )
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(
            f"{len(errors)} violation(s) de pinning ou de durcissement.",
            file=sys.stderr,
        )
        return 1
    print(
        "Pinning OK : Dockerfile, Compose, dépendances Python et actions sont "
        "immuables ; Compose durci."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
