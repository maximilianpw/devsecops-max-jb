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
`DB_NAME`, `DB_USER` et `DB_PASSWORD_FILE` (fichier secret), ou `DB_PASSWORD`
à défaut.

> **État du rapport.** Release `v1.1.0` publiée par la CI le 2026-10-08
> ([run 37784147903](https://github.com/maximilianpw/devsecops-max-jb/actions/runs/37784147903)),
> après `v1.0.0` ([run 37777799398](https://github.com/maximilianpw/devsecops-max-jb/actions/runs/37777799398)). Les sorties brutes des mesures locales
> sont dans [`evidence/`](evidence/). Chaque mesure indique sa date, sa
> commande et la version de l'outil.

## 1. Packages GHCR publics

| Image | Lien | Statut |
| --- | --- | --- |
| API Flask | [`ghcr.io/maximilianpw/devsecops-max-jb`](https://github.com/users/maximilianpw/packages/container/package/devsecops-max-jb) | public, dernière release `v1.1.0` publiée le 2026-10-08 |

Commandes de récupération, sans authentification :

```bash
docker pull ghcr.io/maximilianpw/devsecops-max-jb:1.1.0   # version exacte
docker pull ghcr.io/maximilianpw/devsecops-max-jb:1.1     # alias mineur
docker pull ghcr.io/maximilianpw/devsecops-max-jb:1       # alias majeur
docker pull ghcr.io/maximilianpw/devsecops-max-jb@sha256:451dccc2796cfb0d5c0e65ab683368977afac30604cc354067dfb6ca36943463
```

| Version | Tags | Digest publié | Image auditée (Image ID) | Contenu |
| --- | --- | --- | --- | --- |
| `v1.1.0` | `1.1.0`, `1.1`, `1` | `sha256:451dccc2796cfb0d5c0e65ab683368977afac30604cc354067dfb6ca36943463` | `sha256:e4564d69d8fbbed2af48181cfa371d3ee8ea0ffc152099640a120f86fd165474` | mot de passe lu depuis `DB_PASSWORD_FILE` ; Compose durci, secret fichier ; gate Trivy sur l'image PostgreSQL |
| `v1.0.0` | `1.0.0`, `1.0` | `sha256:3a145abadcb61a994b8c289b7a615f300e036faa42c2c279c39cdfaa0c28034f` | `sha256:ce1ca47843510b426d41d0bffa2fe8de371a11908cd4635e829e0b443ee9f402` | stack durcie et pipeline DevSecOps |

`1.0.0` n'a pas été réécrit par la release `v1.1.0` (même digest qu'à sa
publication, vérifié le 2026-10-08) ; l'alias `1` suit désormais `1.1.0`.

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
« Avant » = commit `fde7f07` (`main`), « après » = branche `feat/harden-stack`.
Dive 0.13.1 avec [`.dive-ci`](.dive-ci), Trivy 0.75.0 sur l'archive
`docker save`.

Image PostgreSQL, mêmes conditions de mesure :

| Critère | Avant | Après |
| --- | --- | --- |
| Image | `postgres:14-alpine` (Alpine 3.24.2, tag mouvant) | `cgr.dev/chainguard/postgres` (Wolfi), épinglée par digest |
| Version | PostgreSQL 14.24 | PostgreSQL 18.6 |
| Taille décompressée (Dive) | 284,6 MB | 379,4 MB |
| Efficacité Dive | 99,89 % | 99,86 % |
| Port publié sur l'hôte | `5432:5432` | aucun (réseau `backend` interne) |
| Utilisateur | démarre en root, serveur sous `postgres` (uid 70) via `gosu` | démarre en root (`User: 0`), serveur sous uid 70 |
| Shell | oui (`sh`, `bash`) | oui (`sh`, `bash`), requis par le script d'entrée de l'image |
| CVE, toutes sévérités | 47 : 1 CRITICAL, 21 HIGH, 22 MEDIUM, 2 LOW, 1 UNKNOWN | 0 détectée |
| HIGH/CRITICAL corrigibles | 22 (toutes dans le binaire Go `gosu`) | 0 |

L'image Chainguard est plus lourde, car elle embarque PostgreSQL 18 et ses
outils. Elle garde un shell pour son script d'initialisation, mais Compose
n'en dépend pas : son healthcheck est en forme exec (§ 4).

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
- l'API utilise `image: ${API_IMAGE:-flask-api:local}` ;
- chaque service Compose est durci (`read_only`, `cap_drop: [ALL]`,
  `no-new-privileges`, `mem_limit`, `pids_limit`, ni `cap_add` ni
  `privileged`), n'utilise pas `env_file` et ne reçoit aucun mot de passe en
  variable d'environnement (clé contenant `PASSWORD` sans suffixe `_FILE`).

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

Les deux healthchecks de [`docker-compose.yml`](docker-compose.yml) sont en
forme exec (`CMD`), sans `CMD-SHELL` : aucun shell n'est nécessaire.

- **API** : l'image ne contient ni shell ni `curl`. Le healthcheck appelle le
  Python du venv :
  `["CMD", "/app/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"]`.
  Une réponse non 2xx ou un délai dépassé lève une exception, donc un code de
  sortie non nul.
- **PostgreSQL** : `["CMD", "/usr/bin/pg_isready", "-h", "127.0.0.1", "-U", …, "-d", …]`.
  `-h 127.0.0.1` est nécessaire, car le socket Unix de l'image Chainguard
  n'est pas au chemin attendu par défaut par `pg_isready`. Utilisateur et base
  sont interpolés par Compose depuis `DB_USER` et `DB_NAME`.
- **Démarrage** : `api-python` attend `db` avec
  `depends_on: condition: service_healthy`.
- **Réseaux** : `db` n'est que sur `backend` (`internal: true`, sans accès
  sortant) ; `api-python` est sur `backend` et `frontend`. Depuis un conteneur
  du réseau `frontend`, `db` n'est pas résolu (vérifié). L'API n'est publiée
  que sur `127.0.0.1:5000`.
- **Identifiants** : `DB_USER` et `DB_NAME` (variables, voir
  [`.env.example`](.env.example)) sont communs à l'API et à PostgreSQL. Le mot
  de passe est un secret Compose de type fichier : `secrets/db_password` (non
  versionné) est monté en `/run/secrets/db_password` et lu via
  `DB_PASSWORD_FILE` (API) et `POSTGRES_PASSWORD_FILE` (PostgreSQL). Il
  n'apparaît ni dans `docker inspect` ni dans l'environnement du processus de
  l'API. Limite : l'entrypoint de l'image PostgreSQL lit le fichier puis
  réexporte `POSTGRES_PASSWORD` dans l'environnement de son propre processus,
  lisible seulement par l'UID 70 et root
  ([`evidence/after/compose-hardening.txt`](evidence/after/compose-hardening.txt)).
  Sans ce fichier, `docker compose up` échoue (message observé sur Docker
  Desktop : `bind source path does not exist`). La source `file:` est imposée :
  Compose refuse de copier un secret `environment:` dans un conteneur
  `read_only` (« `file` is the sole supported option », preuve archivée). Le fichier garde l'UID de
  l'hôte et doit être lisible par les UID 65532 et 70, d'où le mode `0644`.

### Durcissement Compose

Une ancre `x-hardening` est appliquée aux deux services :

| Mesure | `api-python` | `db` |
| --- | --- | --- |
| Système de fichiers | `read_only`, tmpfs `/tmp` | `read_only`, tmpfs `/tmp` et `/var/run/postgresql` |
| Capabilities | `cap_drop: [ALL]` | `cap_drop: [ALL]` |
| Élévation de privilèges | `no-new-privileges:true` | `no-new-privileges:true` |
| Utilisateur | `65532:65532` (image) | `70:70` (forcé) |
| Ressources | `mem_limit: 256m`, `pids_limit: 64` | `mem_limit: 512m`, `pids_limit: 128`, `shm_size: 128m` |

L'image PostgreSQL Chainguard démarre en root pour faire un `chown` du
répertoire de données, ce que `cap_drop: [ALL]` interdit. Le service tourne
donc directement en UID 70 (`postgres`) et le volume est monté sur
`/var/lib/postgresql`, parent de `PGDATA` (`/var/lib/postgresql/data`) qui
appartient déjà à cet utilisateur : `initdb` crée `PGDATA` sans `chown`. Le
volume s'appelle désormais `db-data` ; un ancien volume `db-data-test` est
à supprimer (`docker volume rm <projet>_db-data-test`).

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
| Mot de passe par défaut `testpass` dans le code | plus de valeur par défaut : `DB_PASSWORD_FILE` ou `DB_PASSWORD` doit être fourni |
| Mot de passe visible dans `docker inspect` et l'environnement de l'API | lu depuis le fichier `DB_PASSWORD_FILE` s'il est défini (prioritaire sur `DB_PASSWORD`) ; fichier absent = échec au démarrage |
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
- **pytest** et ses dépendances : retirés de l'image (15 → 9 paquets,
  vérifié par `importlib.metadata` dans l'image finale).

Compatibilité : les tests unitaires passent en Python 3.14 avec ces
dépendances. Les tests d'intégration HTTP passent contre l'image finale,
démarrée par le Compose du dépôt avec PostgreSQL Chainguard 18.6. Image
lancée seule, sans base, `/dbtest` renvoie le 500 générique.

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
- **Trivy** : gate sur l'archive de l'image, sur `requirements.txt` et sur
  l'image PostgreSQL (digest lu dans `docker-compose.yml`, scannée depuis le
  registre) avec `HIGH,CRITICAL`, `--ignore-unfixed`, `--exit-code 1`, sans
  liste d'exclusion. Trivy ne reconnaît pas `requirements-dev.txt` ; ces
  outils ne sont pas embarqués dans l'image. Les rapports complets (toutes
  sévérités) sont archivés même en cas d'échec. Un gate vert signifie
  « aucune HIGH/CRITICAL corrigible », pas « zéro CVE ».
- **Intégration** : nom de projet Compose unique par run, identifiants de
  base générés et masqués à chaque run (mot de passe écrit uniquement dans
  `secrets/db_password`), logs collectés en cas d'échec,
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

Paramètres GitHub configurés par le propriétaire du dépôt (vérifiés par
l'API GitHub le 2026-10-08, non contrôlés par la CI) :

- **`main` protégée** : les 5 jobs de validation (`Flake8 + tests unitaires`,
  `Hadolint + pinning`, `BuildKit + Dive`, `Trivy`, `Compose + pytest`) sont
  des checks obligatoires avant fusion.
- **Tags `v*`** : ruleset `release-tags` actif, sans exception, qui interdit
  la mise à jour et la suppression d'un tag de release. La création reste
  ouverte aux comptes ayant l'accès en écriture ; le job de release refuse
  de toute façon un tag hors de l'historique de `main` ou plus ancien que la
  dernière release.
- **Package GHCR public** : vérifié, le pull anonyme fonctionne.

## 7. Preuves

### Run de release `v1.1.0`

[Run 37784147903](https://github.com/maximilianpw/devsecops-max-jb/actions/runs/37784147903), déclenché par le tag `v1.1.0` sur le
commit `fc3b947` (merge de la PR #4), runners `ubuntu-24.04`, le 2026-10-08.
Les 7 jobs sont en succès. Extraits des logs :

| Job | Extrait |
| --- | --- |
| Flake8 + tests unitaires | `6 passed, 3 deselected` |
| Hadolint + pinning | `hadolint: OK`, `Pinning OK : Dockerfile, Compose et actions sont immuables ; Compose durci.` |
| BuildKit + Dive | `efficiency: 99.7266 %`, `userWastedPercent: 0.4754 %`, `Result:PASS [Total:3] [Passed:2] [Failed:0] [Warn:0] [Skipped:1]` |
| Trivy | gate HIGH/CRITICAL corrigibles : `0` pour `wolfi` et chacun des 9 paquets Python, `0` pour `requirements.txt`, `0` pour `cgr.dev/chainguard/postgres@sha256:0c4eaf6c…` (61 paquets) ; rapports complets dans l'artefact `trivy-reports-1` |
| Compose + pytest | `Image vérifiée : flask-api:ci-fc3b947f406c (sha256:e4564d69…)`, `api-python: healthy`, `db: healthy` (secret fichier en 0644 sur runner Linux), `3 passed` |
| Release GHCR | `1.1.0`, `1.1` et `1` : `sha256:451dccc2796cfb0d5c0e65ab683368977afac30604cc354067dfb6ca36943463` |
| Pull public + smoke test | pull anonyme par tag et par digest (`Digest: sha256:451dccc2…`), puis `{"status":"ok"}` |

Vérification depuis un poste local, sans authentification
(`docker buildx imagetools inspect`) : `1.1.0`, `1.1` et `1` pointent sur
`sha256:451dccc2…` ; `1.0.0` pointe toujours sur `sha256:3a145aba…`.

### Run de release `v1.0.0`

[Run 37777799398](https://github.com/maximilianpw/devsecops-max-jb/actions/runs/37777799398), déclenché par le tag `v1.0.0` sur le
commit `305e539`, runners `ubuntu-24.04`, le 2026-10-08. Les 7 jobs sont en
succès. Extraits des logs :

| Job | Extrait |
| --- | --- |
| Flake8 + tests unitaires | `3 passed, 3 deselected` |
| Hadolint + pinning | `Pinning OK : Dockerfile, Compose et actions sont immuables.` |
| BuildKit + Dive | `efficiency: 99.7266 %`, `userWastedPercent: 0.4754 %`, `Result:PASS [Total:3] [Passed:2] [Failed:0] [Warn:0] [Skipped:1]` |
| Trivy | gate HIGH/CRITICAL corrigibles : `0` pour `wolfi` et chacun des 9 paquets Python ; rapports complets (artefact `trivy-reports-1`) : 0 vulnérabilité, toutes sévérités, image et `requirements.txt` |
| Compose + pytest | `Image vérifiée : flask-api:ci-305e53921a35 (sha256:ce1ca478…)`, `api-python: healthy`, `db: healthy`, `3 passed` |
| Release GHCR | `1.0.0: digest: sha256:3a145abadcb61a994b8c289b7a615f300e036faa42c2c279c39cdfaa0c28034f` ; `1.0` et `1` : même digest |
| Pull public + smoke test | pull anonyme par tag et par digest, puis `{"status":"ok"}` |

Le pull anonyme a aussi été vérifié depuis un poste local
(`docker logout ghcr.io && docker pull ghcr.io/maximilianpw/devsecops-max-jb:1.0.0`),
avec le même digest.

### Mesures locales

Mesures locales du 2026-10-08 (hôte arm64, images `linux/amd64`), toutes sur
la même image API `flask-api:local` (Image ID `sha256:21609806…`).

| Contrôle | Commande | Résultat |
| --- | --- | --- |
| Flake8 | `flake8 --config=.flake8 app.py test_app.py tests scripts` (flake8 7.4.1, Python 3.14) | 0 violation |
| Tests unitaires | `pytest -m "not integration"` (pytest 9.1.1, Python 3.14) | 6 passed |
| Hadolint | `hadolint --config .hadolint.yaml Dockerfile` (2.15.1) | 0 alerte, y compris au seuil `info` |
| Pinning | `scripts/ci/check_pinning.py` | Dockerfile, Compose et actions conformes |
| Dive ≥ 80 % | `dive --ci --ci-config .dive-ci` (0.13.1) | PASS : 99,73 %, 0,48 % d'octets gaspillés |
| Trivy image | gate HIGH/CRITICAL corrigibles (0.75.0) | 0 ; rapport complet : 0 CVE détectée |
| Trivy dépendances | `trivy fs` (détecte `requirements.txt`) | 0 |
| Trivy PostgreSQL | gate HIGH/CRITICAL corrigibles sur l'image Chainguard (0.75.0) | 0 ; rapport complet : 0 CVE détectée |
| Durcissement Compose | `docker inspect`, `/proc/1/status` et `/proc/1/environ` des deux conteneurs, écriture sur `/` et `/app` | `ReadonlyRootfs`, `CapDrop: ALL`, `CapEff=0` et `NoNewPrivs=1` pour `api-python` et `db` ; mot de passe absent de `docker inspect` et de l'environnement de l'API, réexporté par l'entrypoint dans le processus `db` |
| Persistance PostgreSQL | `down` sans `-v` puis `up` | données conservées |
| Utilisateur / shell | `docker image inspect`, `docker run --entrypoint sh` | `65532:65532` ; `sh` introuvable |
| Workflow | `actionlint` 1.7.12 (avec shellcheck) | 0 erreur |
| Services healthy | `docker compose up -d --no-build --wait` avec `API_IMAGE`, identifiants générés et secret `secrets/db_password` en 0644, comme la CI | `api-python` et `db` healthy ; `api-python` exécute l'Image ID audité |
| Tests d'intégration | `pytest -m integration tests/integration` | 3 passed |
| Isolation | connexion à `db:5432` depuis le réseau `frontend` | nom `db` non résolu |
| Smoke test release | image seule, `GET /health` | 200 `{"status":"ok"}` |
| Publication | jobs `Release GHCR` + `Pull public + smoke test` | voir le run de release ci-dessus |

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
| [`after/trivy-db.txt`](evidence/after/trivy-db.txt) | Trivy sur l'image PostgreSQL Chainguard, et gate HIGH/CRITICAL |
| [`after/trivy-deps.txt`](evidence/after/trivy-deps.txt) | Trivy sur `requirements.txt` (renommé : Dependabot lisait l'ancien nom `*requirements*.txt` comme un manifeste pip) |
| [`after/build-cache.txt`](evidence/after/build-cache.txt) | cache des dépendances conservé après modification du code |
| [`after/runtime-compat.txt`](evidence/after/runtime-compat.txt) | même Python, ABI et glibc entre build et image finale |
| [`after/image-run.txt`](evidence/after/image-run.txt) | démarrage en lecture seule |
| [`after/app-functional.txt`](evidence/after/app-functional.txt) | endpoints contre PostgreSQL |
| [`after/compose-hardening.txt`](evidence/after/compose-hardening.txt) | stack Compose durcie : secret absent, healthy, capabilities, lecture seule, intégration, persistance |

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
cp .env.example .env   # DB_USER / DB_NAME (valeurs locales uniquement)
install -d -m 0755 secrets
openssl rand -hex 24 | tr -d '\n' > secrets/db_password
chmod 0644 secrets/db_password   # lu par les UID 65532 (API) et 70 (PostgreSQL)
export API_IMAGE=flask-api:local
docker compose up -d --no-build --wait --wait-timeout 120
pytest -m integration tests/integration
docker compose down --volumes --remove-orphans
```

Variables :

| Variable | Rôle | Défaut |
| --- | --- | --- |
| `API_IMAGE` | Image API utilisée par Compose | `flask-api:local` |
| `DB_USER`, `DB_NAME` | Utilisateur et base, communs à l'API et à PostgreSQL | `testuser`, `testdb` |
| `secrets/db_password` | Fichier du mot de passe PostgreSQL, obligatoire, non versionné | aucun |
| `DB_PASSWORD_FILE` | Lu par l'API, prioritaire sur `DB_PASSWORD` ; fixé par Compose | `/run/secrets/db_password` |
| `DB_PASSWORD` | Repli de l'API hors Compose (ex. exécution directe) | aucun |
| `DB_HOST`, `DB_PORT` | Fixés par Compose | `db`, `5432` |
| `API_BASE_URL` | Cible des tests d'intégration | `http://127.0.0.1:5000` |
| `API_TIMEOUT_SECONDS` | Timeout réseau des tests d'intégration | `5` |

Sur macOS, le port 5000 peut être occupé par AirPlay Receiver. Désactivez-le
ou utilisez un fichier Compose de surcharge local pour le port, puis ajustez
`API_BASE_URL`.

## Licence

[MIT](LICENSE)
