#!/usr/bin/env python3
"""Vérifie que les références externes sont immuables.

- Dockerfile : chaque image de base FROM est épinglée par digest sha256.
- Compose : chaque image externe est épinglée par digest ; PostgreSQL vient de
  Chainguard (cgr.dev/chainguard/postgres). Le service API est exempté car son
  image est celle construite par la CI (API_IMAGE).
- Workflows : chaque action externe est référencée par un SHA de commit complet.

Usage :
    docker compose config --no-interpolate --format json \
        | python3 scripts/ci/check_pinning.py --compose-json -

Code retour non nul si au moins une violation est trouvée.
"""

import argparse
import json
import re
import sys
from pathlib import Path

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
ACTION_SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
DOCKER_ACTION_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
CHAINGUARD_POSTGRES = "cgr.dev/chainguard/postgres"
API_SERVICE = "api-python"
DB_SERVICE = "db"


def logical_lines(text):
    """Fusionne les continuations de ligne et retire les commentaires."""
    text = re.sub(r"\\\r?\n", " ", text)
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def check_dockerfile(path):
    errors = []
    args = {}
    stages = set()
    for line in logical_lines(Path(path).read_text()):
        keyword, _, rest = line.partition(" ")
        keyword = keyword.upper()
        if keyword == "ARG":
            name, _, default = rest.strip().partition("=")
            args[name.strip()] = default.strip().strip("\"'")
            continue
        if keyword != "FROM":
            continue
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument(
        "--compose-json",
        required=True,
        help="sortie de `docker compose config --no-interpolate --format json`"
        " (- pour stdin)",
    )
    parser.add_argument("--workflows", default=".github/workflows")
    options = parser.parse_args()

    if options.compose_json == "-":
        compose = json.load(sys.stdin)
    else:
        compose = json.loads(Path(options.compose_json).read_text())

    errors = (
        check_dockerfile(options.dockerfile)
        + check_compose(compose)
        + check_workflows(options.workflows)
    )
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"{len(errors)} violation(s) de pinning.", file=sys.stderr)
        return 1
    print("Pinning OK : Dockerfile, Compose et actions sont immuables.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
