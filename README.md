# API Flask / PostgreSQL — chaîne DevSecOps

API Flask adossée à PostgreSQL, durcie puis construite, auditée, testée et
publiée sur GHCR par GitHub Actions
([`.github/workflows/ci.yaml`](.github/workflows/ci.yaml)).

| Endpoint | Réponse attendue |
| --- | --- |
| `GET /health` | 200 `{"status":"ok"}` |
| `GET /hello` | 200 `{"message":"Hello world"}` |
| `GET /dbtest` | 200 `{"db_connection":"successful"}` si `SELECT 1` réussit, sinon 500 `{"db_connection":"failed"}` |

L'API est servie par gunicorn sur le port 5000 et lit `DB_HOST`, `DB_PORT`,
`DB_NAME`, `DB_USER` et `DB_PASSWORD`.

> **État du rapport.** Les sections marquées _« À compléter »_ attendent la
> mise à jour de `docker-compose.yml` (PostgreSQL Chainguard, healthchecks) ou
> la première release. Les preuves détaillées de la stack sont dans
> [`evidence/`](evidence/) (apportées par la PR #1). Aucune valeur n'est
> inventée : chaque mesure indique sa date, sa commande et la version de l'outil.

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

Image de l'API, mesurée avec les outils et seuils de la CI :

| Critère | Avant | Après |
| --- | --- | --- |
| Image de base | `python:3.10-slim`, Debian 13.7, tag mouvant | Chainguard Python 3.14.8 (Wolfi), épinglée par digest |
| Taille décompressée (Dive) | 148,2 MB | 86,6 MB (−42 %) |
| Taille compressée (`docker image inspect`) | 54,4 MB | 33,7 MB |
| Utilisateur | root (uid 0, aucun `USER`) | `65532:65532` (nonroot) |
| Shell | oui (`/bin/sh` → `dash`) | non (`exec: "sh": executable file not found`) |
| Outils de paquets | apt, dpkg, pip | aucun exécutable pip/apk ; `ensurepip` et un wheel pip restent présents (voir § 3) |
| Serveur web | serveur de développement Flask | gunicorn |
| Efficacité Dive | 97,35 % | 99,73 % |
| CVE OS, toutes sévérités | 165 (44 HIGH, 58 MEDIUM, 61 LOW, 2 UNKNOWN), 0 corrigible | 0 détectée |
| CVE Python, toutes sévérités | 20 (3 HIGH, 15 MEDIUM, 2 LOW), 20 corrigibles | 0 détectée |
| Gate CI (HIGH/CRITICAL corrigibles) | **échec** : 3 HIGH | réussi : 0 |

« 0 détectée » signifie : aucune CVE, toutes sévérités confondues, trouvée par
Trivy 0.75.0 avec la base publiée le 2026-10-07 07:38 UTC. Trivy n'analyse pas
les bibliothèques natives embarquées dans le wheel `psycopg2-binary` (libpq,
OpenSSL, Kerberos…). Ce n'est donc pas une garantie d'absence totale de CVE.

Conditions de mesure : 2026-10-08, Docker 29.5.3 (containerd image store),
images `linux/amd64` construites en émulation sur un hôte arm64 avec
`docker buildx build --platform linux/amd64 --provenance=false --sbom=false`.
« Avant » = commit `fde7f07` (`main`), « après » = commit `5918246` (PR #1).
Dive 0.13.1 avec [`.dive-ci`](.dive-ci), Trivy 0.75.0 sur l'archive
`docker save`.

_À compléter : image PostgreSQL avant (`postgres:14-alpine`) / après
(Chainguard)._

## 3. Images de base

### Choix de Chainguard

Le Dockerfile comporte deux étapes :

- `cgr.dev/chainguard/python:latest-dev` installe les dépendances. Elle
  contient pip et un shell, et n'est pas conservée dans l'image finale.
- `cgr.dev/chainguard/python:latest` est l'image finale : Python, les
  dépendances et `app.py`. Pas de shell, pas de pip, pas d'apk, pas de
  compilateur.

Les deux étapes reposent sur Wolfi avec Python 3.14.8 (vérifié dans les deux
images). Python, l'ABI `cpython-314` et la glibc 2.44 sont identiques
([`evidence/after/runtime-compat.txt`](evidence/after/runtime-compat.txt)) :
ce qui est installé à la première étape fonctionne tel quel à la seconde.
Avec Distroless, il aurait fallu aligner à la main le Python de build sur le
Python Debian de l'image finale. Chainguard publie aussi une image PostgreSQL
(`cgr.dev/chainguard/postgres`), ce qui garde une seule famille d'images pour
la stack.

### Immuabilité et reproductibilité

Les tags `latest` et `latest-dev` sont mouvants. Les images sont donc
référencées uniquement par digest, avec la version lisible en commentaire :

| Étape | Image | Digest |
| --- | --- | --- |
| build | `python:latest-dev`, Python 3.14.8, relevé le 2026-10-08 | `sha256:894aed3297d91283e1fc4c542f5374a4b5f3726134fda7c94eaa539342be1e05` |
| final | `python:latest`, Python 3.14.8, relevé le 2026-10-08 | `sha256:b6248c85ba9b97e1e61b30197f309cc4d21661f889fefa5268f0a7bc530dad46` |

Ces digests désignent un index OCI multi-architecture (linux/amd64 et
linux/arm64), vérifié avec `docker buildx imagetools inspect`. Mettre à jour
une image revient à changer son digest, ce qui reste visible en revue.

Côté Python, chaque paquet est épinglé à une version exacte, y compris les
dépendances de Flask.

Contraintes vérifiées automatiquement par la CI
([`scripts/ci/check_pinning.py`](scripts/ci/check_pinning.py)) :

- chaque `FROM` du Dockerfile est épinglé par `@sha256:` ;
- PostgreSQL utilise `cgr.dev/chainguard/postgres@sha256:…` et ne publie
  aucun port ;
- l'API utilise `image: ${API_IMAGE:-flask-api:local}`.

### Construction du Dockerfile

- `requirements.txt` est copié avant le code : modifier `app.py` ne relance
  pas l'installation des dépendances
  ([`evidence/after/build-cache.txt`](evidence/after/build-cache.txt)).
- Le venv est créé sans pip, puis rempli par le pip de l'étape de build : pip
  n'arrive jamais dans l'image finale.
- Code et dépendances appartiennent à root (`COPY --from … --chown=0:0`) :
  aucun fichier de `/app` n'est modifiable par l'utilisateur d'exécution
  ([`evidence/after/image.txt`](evidence/after/image.txt)).
- `WORKDIR /app` est placé après les `COPY`, pour que `/app` ne soit pas créé
  au nom de `nonroot`.
- `USER 65532:65532` est numérique, pour qu'un orchestrateur puisse vérifier
  qu'il ne s'agit pas de root.
- Le point d'entrée Python de l'image de base est remplacé par gunicorn, en
  forme exec JSON, avec `--worker-tmp-dir /dev/shm` et `--no-control-socket`.
  Le conteneur démarre ainsi en système de fichiers en lecture seule
  ([`evidence/after/image-run.txt`](evidence/after/image-run.txt)).

### Contexte de build

`.dockerignore` exclut tout par défaut, puis n'autorise que `app.py` et
`requirements.txt`. Il liste ensuite explicitement les fichiers sensibles
(`.env`, clés, `.git`, venvs, caches, tests, logs, archives) comme garde-fou
contre une future exception trop large. Test sur une copie du dépôt avec
`.git` et 15 fichiers parasites : le build ne reçoit que `app.py` et
`requirements.txt` ([`evidence/after/dockerignore.txt`](evidence/after/dockerignore.txt)).

### Limites connues

- Le Python de l'image de base embarque le module `ensurepip` et un wheel
  `pip-26.2.1`. Sans shell, ils ne peuvent pas être retirés de l'image finale.
  `python -m ensurepip` échoue, car aucun dossier Python n'est accessible en
  écriture.
- `psycopg2-binary` embarque ses propres bibliothèques natives, non analysées
  par Trivy. Les couvrir imposerait de compiler `psycopg2` contre la libpq de
  Wolfi.

## 4. Runtime sans shell

_À compléter : healthchecks exec de l'API et de PostgreSQL (sans
`sh`/`curl`), ordre de démarrage (`depends_on: condition: service_healthy`)._
L'image API ne contient ni shell ni `curl`. Son healthcheck doit donc appeler
l'interpréteur Python du venv en forme exec, par exemple :

```yaml
healthcheck:
  test: ["CMD", "/app/venv/bin/python", "-c",
         "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2)"]
```

La CI démarre la stack avec `docker compose up -d --no-build --wait
--wait-timeout 120`, puis exige l'état `healthy` explicite des deux services.
Un service sans healthcheck fait échouer le job.

## 5. Remédiations

### Flake8

Avec le `.flake8` fourni, qui ignore notamment E302, W293 et W391, le code
initial passait déjà. Les 6 violations masquées par ces exclusions dans
`app.py` (4 × E302, W293, W391) ont quand même été corrigées : `app.py` et les
tests passent aussi en `flake8 --isolated --max-line-length 88`. Le fichier
`.flake8` n'a pas été modifié.

### Code de l'application

| Problème | Correction |
| --- | --- |
| Connexion et curseur PostgreSQL non fermés en cas d'erreur | `contextlib.closing` les ferme dans tous les cas |
| Message d'erreur brut (hôte, utilisateur, base) renvoyé au client | réponse fixe `{"db_connection": "failed"}` ; le détail part dans les logs |
| `except Exception` trop large | seules les erreurs `psycopg2.Error` sont attrapées |
| Mot de passe par défaut `testpass` dans le code | plus de valeur par défaut : `DB_PASSWORD` doit être fourni |
| Base injoignable bloquant la requête | délai de connexion de 5 secondes |
| `app.run(host="0.0.0.0")` : serveur de développement | supprimé, gunicorn sert l'API |

### Tests

| Constat initial | Correction |
| --- | --- |
| Le test `/dbtest` passait par le client Flask en mémoire et cherchait l'hôte `db` depuis le runner | tests HTTP réels contre l'API conteneurisée (`tests/integration/`) |
| Tests limités au code HTTP | vérification du code HTTP et du JSON exact |
| pytest dans les dépendances runtime | outils déplacés dans `requirements-dev.txt` |

### Dépendances

CVE Python relevées par Trivy dans l'image initiale :

| Paquet | Version | Origine | CVE | Traitement |
| --- | --- | --- | --- | --- |
| Werkzeug | 2.3.3 | `requirements.txt` | CVE-2024-34069 (HIGH) ; CVE-2023-46136, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 (MEDIUM) | 3.1.9 |
| Flask | 2.3.2 | `requirements.txt` | CVE-2026-27205 (LOW) | 3.1.3 |
| pytest | 7.4.0 | `requirements.txt` | CVE-2025-71176 (MEDIUM) | retiré du runtime |
| pip | 23.0.1 | image de base | CVE-2023-5752, CVE-2025-8869, CVE-2026-13346, CVE-2026-3219, CVE-2026-6357, CVE-2026-8643 (MEDIUM) ; CVE-2026-1703 (LOW) | absent de l'image finale |
| setuptools | 79.0.1 | image de base | CVE-2026-59890 (MEDIUM) | absent de l'image finale |
| wheel (copie dans setuptools) | 0.45.1 | image de base | CVE-2026-24049 (HIGH) | absent de l'image finale |
| jaraco.context (copie dans setuptools) | 5.3.0 | image de base | CVE-2026-23949 (HIGH) | absent de l'image finale |

Les 165 CVE Debian n'avaient aucun correctif disponible : elles disparaissent
avec le changement d'image de base.

Choix des versions :

- **Werkzeug 3.1.9** : corrige les 8 CVE relevées.
- **Flask 3.1.3** : corrige sa CVE ; Flask 3.1 requiert `werkzeug>=3.1.0`.
- **psycopg2-binary 2.9.13** : n'était pas épinglé ; désormais fixé, wheel
  disponible pour Python 3.14.
- **gunicorn 26.2.0** : remplace le serveur de développement Flask.
- **blinker, click, itsdangerous, Jinja2, MarkupSafe** : dépendances de Flask,
  désormais épinglées.
- **pytest** et ses dépendances : retirés de l'image (15 → 9 paquets).

Compatibilité : les tests unitaires passent en Python 3.14 avec ces
dépendances. Les tests d'intégration HTTP passent contre l'image finale,
lors d'un test local avec un Compose temporaire conforme au contrat et
PostgreSQL 14 (`postgres:14-alpine`). Base
arrêtée, `/dbtest` renvoie le 500 générique. _À compléter : même vérification
avec PostgreSQL Chainguard._

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
  commentaire), vérifié par la CI. Hadolint 2.15.1, Dive 0.13.1 et Trivy
  0.75.0 sont téléchargés depuis leurs releases officielles avec un SHA256
  épinglé dans le workflow.
- **Python de la CI** : 3.14, aligné sur l'image runtime.
- **Ordre des gates** : aucun build ni conteneur avant le succès de Flake8,
  des tests unitaires, de Hadolint et du pinning.
- **Hadolint** : règles DL3002, DL3006, DL3007 et DL4006 forcées en `error`,
  SC2086 remontée en `warning` ; aucune règle désactivée, chaque règle testée
  sur un Dockerfile fautif
  ([`evidence/after/hadolint.txt`](evidence/after/hadolint.txt)). Hadolint
  laisse passer un tag mouvant comme `python:3.10-slim` et un conteneur root
  sans ligne `USER` : le pinning est donc vérifié par
  `check_pinning.py`, et l'utilisateur par inspection de l'image.
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

Mesures locales du 2026-10-08 (hôte arm64, images `linux/amd64`), sauf
mention contraire. Les preuves CI seront ajoutées après le premier run vert.

| Contrôle | Commande | Résultat |
| --- | --- | --- |
| Flake8 | `flake8 --config=.flake8 app.py test_app.py tests scripts` (flake8 7.4.1, Python 3.14) | 0 violation |
| Tests unitaires | `pytest -m "not integration"` (pytest 9.1.1, Python 3.14) | 3 passed |
| Hadolint | `hadolint --config .hadolint.yaml Dockerfile` (2.15.1) | 0 alerte, y compris au seuil `info` |
| Pinning | `scripts/ci/check_pinning.py` | Dockerfile conforme ; _Compose : à compléter_ |
| Dive ≥ 80 % | `dive --ci --ci-config .dive-ci` (0.13.1) | PASS : 99,73 %, 0,48 % d'octets gaspillés |
| Trivy image | gate HIGH/CRITICAL corrigibles (0.75.0) | 0 ; rapport complet : 0 CVE détectée |
| Trivy dépendances | `trivy fs` sur `requirements*.txt` | 0 |
| Utilisateur / shell | `docker image inspect`, `docker run --entrypoint sh` | `65532:65532` ; `sh` introuvable |
| Workflow | `actionlint` 1.7.12 (avec shellcheck) | 0 erreur |
| Tests d'intégration | `pytest -m integration tests/integration` | _À compléter (run CI avec le Compose final)_ |
| Services healthy | job `Compose + pytest` | _À compléter_ |
| Publication | jobs `Release GHCR` + `Pull public + smoke test` | _À compléter_ |

Preuves détaillées de la stack ([`evidence/`](evidence/)) :

| Fichier | Contenu |
| --- | --- |
| [`before/`](evidence/before/) | état initial : Flake8, Hadolint, image, paquets, Dive, Trivy |
| [`after/flake8.txt`](evidence/after/flake8.txt) | Flake8 après correction |
| [`after/hadolint.txt`](evidence/after/hadolint.txt) | Hadolint et test de chaque règle sur des Dockerfiles fautifs |
| [`after/dockerignore.txt`](evidence/after/dockerignore.txt) | fichiers reçus par le build malgré des fichiers parasites |
| [`after/image.txt`](evidence/after/image.txt) | taille, utilisateur, shell, binaires, permissions |
| [`after/dive.txt`](evidence/after/dive.txt) | Dive en mode CI |
| [`after/trivy.txt`](evidence/after/trivy.txt) | Trivy sur l'image finale |
| [`after/trivy-requirements.txt`](evidence/after/trivy-requirements.txt) | Trivy sur `requirements.txt` |
| [`after/build-cache.txt`](evidence/after/build-cache.txt) | cache des dépendances conservé après modification du code |
| [`after/runtime-compat.txt`](evidence/after/runtime-compat.txt) | même Python, ABI et glibc entre build et image finale |
| [`after/image-run.txt`](evidence/after/image-run.txt) | démarrage en lecture seule |
| [`after/app-functional.txt`](evidence/after/app-functional.txt) | endpoints contre PostgreSQL |

## Reproduction locale

Prérequis : Docker avec Compose v2 et BuildKit, Python 3.14, Hadolint
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
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` | Connexion de l'API à PostgreSQL | voir `docker-compose.yml` |
| `DB_PASSWORD` | Mot de passe PostgreSQL, obligatoire | aucun |
| `API_BASE_URL` | Cible des tests d'intégration | `http://127.0.0.1:5000` |
| `API_TIMEOUT_SECONDS` | Timeout réseau des tests d'intégration | `5` |

Sur macOS, le port 5000 peut être occupé par AirPlay Receiver. Désactivez-le
ou utilisez un fichier Compose de surcharge local pour le port, puis ajustez
`API_BASE_URL`.

## Licence

[MIT](LICENSE)
