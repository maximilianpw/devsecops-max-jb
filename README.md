# API Flask / PostgreSQL — chaîne DevSecOps

API Flask (`/health`, `/hello`, `/dbtest`) adossée à PostgreSQL, construite,
auditée, testée puis publiée sur GHCR par GitHub Actions
([`.github/workflows/ci.yaml`](.github/workflows/ci.yaml)).

> **État du rapport.** Les sections marquées _« À compléter »_ attendent soit
> la stack durcie (Dockerfile, Compose, dépendances), soit la première release
> publiée. Aucune valeur n'y est inventée : seules les mesures réellement
> exécutées sont reportées, avec leur date et la version des outils.

## 1. Packages GHCR publics

| Image | Lien | Statut |
| --- | --- | --- |
| API Flask | `ghcr.io/maximilianpw/devsecops-max-jb` | _À compléter : aucune release publiée_ |

Commandes de récupération (à confirmer après la première release `vX.Y.Z`) :

```bash
docker pull ghcr.io/maximilianpw/devsecops-max-jb:X.Y.Z     # version exacte
docker pull ghcr.io/maximilianpw/devsecops-max-jb@sha256:…  # digest immuable
```

Tags publiés pour une release `vX.Y.Z` : `X.Y.Z`, `X.Y` et `X`. Seul le digest
est immuable. `X.Y.Z` n'est jamais réécrit. Les alias `X.Y` et `X` suivent la
dernière release stable de leur branche de versions.

## 2. Avant / après

| Critère | Avant (image initiale) | Après (image durcie) |
| --- | --- | --- |
| Image de base | `python:3.10-slim` (Debian 13.7, tag mouvant) | _À compléter (A)_ |
| Taille | 223 MB (`docker image ls`, Docker 29, linux/amd64) | _À compléter_ |
| Utilisateur | `root` (uid 0, aucun `USER`) | _À compléter_ |
| Shell présent | Oui (`/bin/sh` → `dash`) | _À compléter_ |
| Efficacité Dive | 97,36 % (5,7 MB gaspillés) | _À compléter_ |
| CVE OS (Debian) | 165 : 44 HIGH, 58 MEDIUM, 61 LOW, 2 UNKNOWN ; 0 corrigible | _À compléter_ |
| CVE Python | 20 : 3 HIGH, 15 MEDIUM, 2 LOW ; toutes corrigibles | _À compléter_ |
| HIGH/CRITICAL corrigibles (gate) | **3** → gate Trivy en échec | _À compléter_ |

CVE HIGH corrigibles relevées sur l'image initiale :

| Paquet | Version | CVE | Version corrigée |
| --- | --- | --- | --- |
| Werkzeug | 2.3.3 | CVE-2024-34069 | 3.0.3 |
| jaraco.context | 5.3.0 | CVE-2026-23949 | 6.1.0 |
| wheel | 0.45.1 | CVE-2026-24049 | 0.46.2 |

`jaraco.context` et `wheel` proviennent de l'outillage pip/setuptools de
l'image de base, pas de `requirements.txt`.

Mesures « avant » : 2026-10-08, image construite depuis `fde7f07` avec
`docker build --platform linux/amd64`, Dive 0.13.1, Trivy 0.75.0
(base de vulnérabilités du 2026-10-08), sur l'archive `docker save`.

## 3. Images de base

_À compléter (A)_ : choix Distroless/Chainguard, versions, digests,
compatibilité builder/runtime (version de Python, ABI de `psycopg2`) et
reproductibilité.

Contraintes vérifiées automatiquement par la CI
([`scripts/ci/check_pinning.py`](scripts/ci/check_pinning.py)) :

- chaque `FROM` du Dockerfile est épinglé par `@sha256:` ;
- PostgreSQL utilise `cgr.dev/chainguard/postgres@sha256:…` et ne publie
  aucun port ;
- l'API utilise `image: ${API_IMAGE:-flask-api:local}`.

## 4. Runtime sans shell

_À compléter (A)_ : healthchecks exec de l'API et de PostgreSQL (sans
`sh`/`curl`), ordre de démarrage (`depends_on: condition: service_healthy`).

La CI démarre la stack avec `docker compose up -d --no-build --wait
--wait-timeout 120`, puis exige l'état `healthy` explicite des deux services.
Un service sans healthcheck fait échouer le job.

## 5. Remédiations

| Sujet | Constat initial | Correction | Statut |
| --- | --- | --- | --- |
| Flake8 | Code initial conforme à `.flake8`, qui ignore E302/W292 ; le test initial n'est conforme que grâce à ces exclusions | Tests réécrits au format PEP 8 sans dépendre de ces exclusions ; `.flake8` inchangé | Fait |
| Test `/dbtest` | Exécuté via le client Flask en mémoire, cherchait l'hôte `db` depuis le runner | Remplacé par un test HTTP contre l'API conteneurisée | Fait |
| pytest en runtime | `pytest` dans `requirements.txt` | Outils déplacés dans `requirements-dev.txt` ; retrait côté runtime | _À faire (A)_ |
| `psycopg2-binary` non épinglé | Version non reproductible, invisible pour le scan de manifeste Trivy | Épinglage | _À faire (A)_ |
| CVE Werkzeug / outillage pip | 3 HIGH corrigibles (§ 2) | Montée de version et image runtime sans outillage | _À compléter (A)_ |

## 6. Sécurité CI/CD

Graphe du workflow :

```text
Flake8 + tests unitaires ─┐
                          ├─ BuildKit + Dive ─┬─ Trivy ────────────┐
Hadolint + pinning ───────┘                   └─ Compose + pytest ─┼─ Release GHCR ─ Pull public + smoke test
                                                                   │
                          (release : tags vX.Y.Z uniquement) ──────┘
```

- **Déclencheurs** : push sur `main`, PR vers `main` (`pull_request`, jamais
  `pull_request_target`), tags `vX.Y.Z`. Les PR et les pushes valident sans
  publier.
- **Permissions** : `permissions: {}` au niveau du workflow ;
  `contents: read` par job ; `packages: write` uniquement pour le job de
  release ; aucune permission pour la vérification publique.
  `persist-credentials: false` sur chaque checkout.
- **Pinning** : actions externes référencées par SHA complet (version en
  commentaire), vérifié par la CI. Hadolint, Dive et Trivy sont téléchargés
  depuis leurs releases officielles avec un SHA256 épinglé dans le workflow.
- **Ordre des gates** : aucun build ni conteneur avant le succès de Flake8,
  des tests unitaires, de Hadolint et du pinning.
- **Une seule image** : construite une fois (BuildKit, `linux/amd64`, sans
  attestations), exportée par `docker save`, transmise en artefact. Chaque job
  consommateur vérifie le SHA256 de l'archive puis l'Image ID avant usage ;
  le job d'intégration vérifie aussi que le conteneur `api-python` exécute
  bien cet Image ID. La release retague cette image, sans reconstruction.
- **Dive** ([`.dive-ci`](.dive-ci)) : `lowestEfficiency: 0.8` (exigence),
  `highestUserWastedPercent: 0.1` (défaut Dive rendu explicite),
  `highestWastedBytes: disabled`. Le défaut implicite de Dive pour
  l'efficacité (0.9) n'est donc pas appliqué.
- **Trivy** : gate sur l'archive de l'image et sur les manifestes Python
  (`HIGH,CRITICAL`, `--ignore-unfixed`, `--exit-code 1`), sans liste
  d'exclusion. Les rapports complets (toutes sévérités) sont archivés même en
  cas d'échec. Un gate vert signifie « aucune HIGH/CRITICAL corrigible », pas
  « zéro CVE ».
- **Intégration** : nom de projet Compose unique par run, identifiants de
  base générés et masqués à chaque run, logs collectés en cas d'échec,
  `docker compose down --volumes --remove-orphans` systématique.
- **Release SemVer** :
  - tag strictement validé ;
  - commit obligatoirement dans l'historique de `main` ;
  - releases sérialisées (`concurrency`) ;
  - refus si le tag n'est pas la release stable la plus récente, pour que les
    alias ne reculent jamais ;
  - refus si `X.Y.Z` existe déjà sur GHCR ;
  - authentification par `GITHUB_TOKEN` ;
  - contrôle que `X.Y` et `X` pointent vers le digest publié.
  - Le job suivant fait un `docker pull` anonyme par tag et par digest, puis
    un smoke test sur `/health`.

Paramètres GitHub à configurer par un administrateur du dépôt (non vérifiés
par la CI) :

- règle de protection des tags `v*` (création réservée aux mainteneurs, ni
  suppression ni mise à jour) ;
- protection de `main` avec les jobs du workflow comme checks requis ;
- visibilité **publique** du package GHCR après la première publication.

## 7. Preuves

| Contrôle | Commande | Résultat | Date |
| --- | --- | --- | --- |
| Flake8 | `flake8 --config=.flake8 app.py test_app.py tests scripts` | 0 violation (local, Python 3.12) | 2026-10-08 |
| Tests unitaires | `pytest -m "not integration"` | 3 passed | 2026-10-08 |
| Tests d'intégration | `pytest -m integration tests/integration` | 3 passed (stack initiale, local) | 2026-10-08 |
| Workflow | `actionlint` 1.7.12 (avec shellcheck) | 0 erreur | 2026-10-08 |
| Hadolint | `hadolint --config .hadolint.yaml Dockerfile` | _À compléter (`.hadolint.yaml` de A)_ | |
| Pinning | `scripts/ci/check_pinning.py` | Stack initiale : 5 violations attendues ; _après : à compléter_ | 2026-10-08 |
| Dive ≥ 80 % | `dive --ci --ci-config .dive-ci` | Initiale : PASS (97,36 %) ; _après : à compléter_ | 2026-10-08 |
| Trivy | gate HIGH/CRITICAL corrigibles | Initiale : **échec** (3 HIGH) ; _après : à compléter_ | 2026-10-08 |
| Services healthy | job `Compose + pytest` | _À compléter (run CI)_ | |
| Publication | jobs `Release GHCR` + `Pull public + smoke test` | _À compléter (release)_ | |

## Reproduction locale

Prérequis : Docker avec Compose v2 et BuildKit, Python ≥ 3.10, Hadolint
2.15.1, Dive 0.13.1, Trivy 0.75.0.

```bash
# Qualité et tests unitaires (sans base)
python -m pip install -r requirements.txt -r requirements-dev.txt
flake8 --config=.flake8 app.py test_app.py tests scripts
pytest -m "not integration"

# Gates statiques
hadolint --config .hadolint.yaml Dockerfile
docker compose config --no-interpolate --format json \
  | python3 scripts/ci/check_pinning.py --compose-json -

# Build unique, Dive, Trivy
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  --load -t flask-api:local .
dive --ci --ci-config .dive-ci flask-api:local
docker save -o image.tar flask-api:local
trivy image --input image.tar --scanners vuln \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1

# Stack réelle et tests HTTP
export API_IMAGE=flask-api:local
docker compose up -d --no-build --wait --wait-timeout 120
pytest -m integration tests/integration
docker compose down --volumes --remove-orphans
```

Variables :

| Variable | Rôle | Défaut |
| --- | --- | --- |
| `API_IMAGE` | Image API utilisée par Compose | `flask-api:local` |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | Connexion de l'API à PostgreSQL | voir `docker-compose.yml` |
| `API_BASE_URL` | Cible des tests d'intégration | `http://127.0.0.1:5000` |
| `API_TIMEOUT_SECONDS` | Timeout réseau des tests d'intégration | `5` |

Sur macOS, le port 5000 peut être occupé par AirPlay Receiver. Désactivez-le
ou utilisez un fichier Compose de surcharge local pour le port, puis ajustez
`API_BASE_URL`.

## Licence

[MIT](LICENSE)
