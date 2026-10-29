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
> commande et la version de l'outil. Le TP2 (build Bake, secret BuildKit,
> amd64 + arm64, index multi-plateforme) est décrit au § 8, le SBOM, Grype et
> le VEX au § 9 ; aucune release multi-architecture n'est encore publiée.

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
| Image de base | `python:3.10-slim`, Debian 13.7, tag mouvant | Chainguard Python 3.15.0 (Wolfi), épinglée par digest |
| Taille décompressée (Dive) | 148,2 MB | 90,4 MB (−39 %) |
| Taille compressée (`docker image inspect`) | 54,4 MB | 35,1 MB |
| Utilisateur | root (uid 0, aucun `USER`) | `65532:65532` (nonroot) |
| Shell | oui (`/bin/sh` → `dash`) | non (`exec: "sh": executable file not found`) |
| Outils de paquets | apt, dpkg, pip | aucun exécutable pip/apk ; `ensurepip` et un wheel pip restent présents (voir § 3) |
| Serveur web | serveur de développement Flask | gunicorn |
| Efficacité Dive | 97,35 % | 99,72 % |
| CVE OS, toutes sévérités | 165 (44 HIGH, 58 MEDIUM, 61 LOW, 2 UNKNOWN), 0 corrigible | 0 détectée |
| CVE Python, toutes sévérités | 20 (3 HIGH, 15 MEDIUM, 2 LOW), 20 corrigibles | 0 détectée |
| Gate CI (HIGH/CRITICAL corrigibles) | **échec** : 3 HIGH | réussi : 0 |

« 0 détectée » signifie : aucune CVE, toutes sévérités confondues, trouvée par
Trivy 0.75.0 avec la base publiée le 2026-10-26 07:15 UTC. Trivy n'analyse pas
les bibliothèques natives embarquées dans le wheel `psycopg2-binary` (libpq,
OpenSSL, Kerberos…). Ce n'est donc pas une garantie d'absence totale de CVE.

Conditions de mesure : « avant » le 2026-10-08, « après » le 2026-10-26
(images de base mises à jour, voir § 3), Docker 29.5.3 (containerd image store),
images `linux/amd64` construites en émulation sur un hôte arm64 avec
`docker buildx build --platform linux/amd64 --provenance=false --sbom=false`.
« Avant » = commit `fde7f07`, « après » = digests Chainguard du 2026-10-26.
Dive 0.13.1 avec [`.dive-ci`](.dive-ci), Trivy 0.75.0 sur l'archive
`docker save`.

Image PostgreSQL, mêmes conditions de mesure :

| Critère | Avant | Après |
| --- | --- | --- |
| Image | `postgres:14-alpine` (Alpine 3.24.2, tag mouvant) | `cgr.dev/chainguard/postgres` (Wolfi), épinglée par digest |
| Version | PostgreSQL 14.24 | PostgreSQL 18.6 |
| Taille décompressée (Dive) | 284,6 MB | 361,7 MB ([`dive-db.txt`](evidence/after/dive-db.txt)) |
| Efficacité Dive | 99,89 % | 99,85 % |
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

Les deux étapes reposent sur Wolfi avec Python 3.15.0 (vérifié dans les deux
images). Python, l'ABI `cpython-315` et la glibc 2.44 sont identiques
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
| build | `python:latest-dev`, Python 3.15.0, relevé le 2026-10-26 | `sha256:dde1a2549dd62864f0263dae8e877680837b4e738a7ecc85c671c55c069848ac` |
| final | `python:latest`, Python 3.15.0, relevé le 2026-10-26 | `sha256:49fd266eb8a1331194c318b742087c7a2939cc5794fa64f17feb9e17e12703e2` |

Ces digests désignent un index OCI multi-architecture (linux/amd64 et
linux/arm64), vérifié avec `docker buildx imagetools inspect`. Mettre à jour
une image revient à changer son digest, ce qui reste visible en revue.

**Mise à jour du 2026-10-26.** Les digests du 2026-10-08 sont restés figés
pendant que des CVE étaient publiées : le gate Trivy a bloqué la CI avec
4 HIGH corrigibles dans chacune des deux images (`ca-certificates-bundle`
CVE-2026-111943, `libbrotli*` CVE-2026-111497), API et PostgreSQL. Les trois
digests ont été mis à jour ; les nouvelles images ne contiennent aucune CVE
détectée. Chainguard ne publie gratuitement que les tags `latest` et
`latest-dev` : la mise à jour fait passer Python de 3.14.8 à 3.15.0. Toutes
les dépendances ont une roue `cp315` (aucune compilation), la CI passe à
Python 3.15, et les preuves de `evidence/after/` ont été régénérées sur la
nouvelle image avec
[`scripts/evidence/regenerate.sh`](scripts/evidence/regenerate.sh).

Côté Python, chaque paquet est épinglé à une version exacte, y compris les
dépendances de Flask.

Contraintes vérifiées automatiquement par la CI
([`scripts/ci/check_pinning.py`](scripts/ci/check_pinning.py)) :

- chaque `FROM` du Dockerfile est épinglé par `@sha256:`, et aucune
  instruction `ADD` n'est acceptée. Le Dockerfile est lu comme BuildKit
  (BOM ignoré, commentaires retirés avant les continuations, continuation
  concaténée sans séparateur, mot-clé séparé par tout blanc,
  contexte différé de `ONBUILD` conservé,
  heredocs reconnus en forme shell de `RUN`/`COPY`/`ADD` avec leur délimiteur
  complet et un descripteur composé de chiffres ASCII). Toute syntaxe ambiguë est **refusée** plutôt qu'interprétée :
  directive de parseur (`# escape=`, ou `# syntax=` autre que
  `docker/dockerfile:1[.x[.y]]@sha256:…` en toute première ligne, seule forme
  acceptée et exigée en CI par `--require-tp2`), échappement final doublé, délimiteur de heredoc
  autre qu'un nom simple, ligne d'ouverture de heredoc non lexicalement
  simple (`$`, backtick, antislash, guillemet non fermé : BuildKit y
  abandonne le heredoc), heredoc non terminé, caractère de contrôle ou
  d'espacement autre que espace, tabulation et LF (CR, tabulation verticale,
  espace insécable, séparateurs Unicode : Python et BuildKit ne les lisent pas
  de la même façon). 25 cas sont comparés à
  BuildKit dans [`evidence/after/hadolint.txt`](evidence/after/hadolint.txt) ;
- chaque ligne de `requirements.txt` et `requirements-dev.txt` est de la
  forme `nom==version` ;
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
  `pip-26.2.2`. Sans shell, ils ne peuvent pas être retirés de l'image finale.
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
  disponible pour Python 3.15 (`cp315`).
- **gunicorn 26.2.0** : remplace le serveur de développement Flask.
- **blinker, click, itsdangerous, Jinja2, MarkupSafe** : dépendances de Flask,
  désormais épinglées.
- **pytest** et ses dépendances : retirés de l'image (15 → 9 paquets,
  vérifié par `importlib.metadata` dans l'image finale).

Compatibilité : les tests unitaires passent en Python 3.15 avec ces
dépendances. Les tests d'intégration HTTP passent contre l'image finale,
démarrée par le Compose du dépôt avec PostgreSQL Chainguard 18.6. Image
lancée seule, sans base, `/dbtest` renvoie le 500 générique.

## 6. Sécurité CI/CD

Graphe du workflow :

```text
Flake8 + tests unitaires ─┐  ┌─ build-amd64 (ubuntu-24.04)     ─ scan-amd64 ─┐   ┌─ BuildKit + Dive ─┐
                          ├──┤                                               ├───┼─ Trivy ───────────┼─ Publish validated multi-platform index
Hadolint + pinning ───────┘  └─ build-arm64 (ubuntu-24.04-arm) ─ scan-arm64 ─┘   └─ Compose + pytest ─┘     └─ Anonymous pull and native smoke test
                                                                       (publication : tags vX.Y.Z uniquement)
```

`build-*` = Bake, preuves secret/cache et intégration Compose native ;
`scan-*` = Dive et Trivy sur l'archive transmise (détails au § 8).
`BuildKit + Dive`, `Trivy` et `Compose + pytest` sont désormais des jobs
agrégateurs (`if: always()`) qui n'échouent pas seulement en cas d'erreur :
ils exigent le succès explicite de chaque producteur des deux architectures.
Un job sauté, annulé ou absent les fait échouer.

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
- **Python de la CI** : 3.15, aligné sur l'image runtime.
- **Ordre des gates** : aucun build ni conteneur avant le succès de Flake8,
  des tests unitaires, de Hadolint et du pinning (`--require-tp2`). Ensuite :
  build et intégration native par architecture, scans des deux archives,
  agrégateurs, puis publication sur tag seulement.
- **Hadolint** : politique d'équipe écrite dans
  [`.hadolint.yaml`](.hadolint.yaml), chaque règle commentée avec sa raison :

  | Règle d'équipe | Codes forcés en `error` |
  | --- | --- |
  | R1 Images de base : registre `cgr.dev` seul, tag ou digest explicite, `latest` seul refusé | DL3026, DL3006, DL3007 |
  | R2 Exécution sans privilèges | DL3002, DL3004 |
  | R3 Shell robuste | DL4006, SC2086, DL3003, DL4001 |
  | R4 Copie maîtrisée (`COPY` uniquement) | DL3020, DL3021, DL3022, DL3045, DL3000 |
  | R5 Dépendances Python versionnées, cache pip jamais dans une couche | DL3013, DL3042 |
  | R6 Démarrage prévisible (forme JSON, au plus un `CMD` et un `ENTRYPOINT` par étape) | DL3025, DL4003, DL4004 |

  Seuil `failure-threshold: style` : toute autre alerte Hadolint, quel que
  soit son niveau (jusqu'à `style`), bloque aussi. `ignored: []` et
  `disable-ignore-pragma: true` : aucune exception possible, ni dans la
  configuration, ni par commentaire `# hadolint ignore=` dans le Dockerfile.

  Hadolint ignore sans erreur une clé ou un code mal saisi. Le script
  [`check_hadolint_policy.py`](scripts/ci/check_hadolint_policy.py), exécuté
  en CI :
  - lit `.hadolint.yaml` dans un format strict (ligne non reconnue, code mal
    formé ou entre guillemets refusés) et en vérifie les invariants : seuil
    `style`, `ignored: []`, pragmas désactivés, `cgr.dev` seul registre,
    surcharges uniquement en `error` ;
  - exige que les règles forcées en `error` soient exactement celles testées ;
  - rejoue chaque règle sur un Dockerfile qui ne viole qu'elle et exige
    cette seule alerte, en `error`, avec échec de Hadolint ;
  - vérifie que le seuil `style` (DL3048) et le refus des pragmas sont
    effectifs.

  Treize mutations de la configuration (règle retirée, ajoutée sans test ou
  entre guillemets, code ou clé mal saisis, pragmas autorisés, seuil relevé,
  règle désactivée, registre ajouté, surcharge hors `error`, clé ou sous-clé
  dupliquée) font toutes échouer ce contrôle
  ([`evidence/after/hadolint.txt`](evidence/after/hadolint.txt)).

  Limites de Hadolint, couvertes ailleurs : un tag sans digest du registre
  autorisé (`cgr.dev/chainguard/python:latest-dev`) et `ADD` d'une URL ou
  d'une archive passent Hadolint, mais sont refusés par `check_pinning.py` ;
  DL3013 accepte `Flask>=3` et ne lit pas `-r requirements.txt`, d'où
  l'exigence `==` de `check_pinning.py` ; un conteneur sans ligne `USER`
  passe aussi, l'utilisateur est vérifié par inspection de l'image.
- **Une image par architecture** : chaque variante est construite une fois
  (Bake `app-ci`, sans attestations), exportée par `docker save` et transmise
  en artefact. Chaque consommateur vérifie le SHA256 de l'archive, l'Image ID,
  la plateforme, les DiffIDs et les métadonnées (commit, run, tentative),
  avec des valeurs attendues issues des outputs du job producteur, jamais de
  l'artefact. Le job d'intégration vérifie aussi que le conteneur `api-python`
  exécute bien cet Image ID. La release publie ces archives, sans
  reconstruction (§ 8).
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
  - refus si `X.Y.Z` existe déjà sur GHCR ; une erreur d'authentification
    ou réseau n'est jamais prise pour « tag absent » ;
  - authentification par `GITHUB_TOKEN` ;
  - publication d'un index multi-plateforme, puis contrôle que `X.Y.Z`, `X.Y`
    et `X` pointent vers son digest.
  - Le job suivant fait, sur chaque architecture, un `docker pull` anonyme
    par tag et par digest, un smoke test sur `/health` et le contrôle du
    config digest attendu.

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

Mesures locales du 2026-10-26 (hôte arm64, images `linux/amd64`), toutes sur
la même image API `flask-api:local` (Image ID `sha256:f6dd57fe…`), régénérées
par [`scripts/evidence/regenerate.sh`](scripts/evidence/regenerate.sh).

| Contrôle | Commande | Résultat |
| --- | --- | --- |
| Flake8 | `flake8 --config=.flake8 app.py test_app.py tests scripts` (flake8 7.4.1, Python 3.15) | 0 violation |
| Tests unitaires | `pytest -m "not integration"` (pytest 9.1.1, Python 3.15) | 78 passed : 6 pour l'application, 72 pour les contrôles de CI ([`tests/test_ci_scripts.py`](tests/test_ci_scripts.py) : contournements de `check_pinning.py` et mutations de `.hadolint.yaml`) ; dans le job CI sans Hadolint, seule la variante du test des alertes en double qui appelle le vrai binaire est ignorée ; une variante simulée s'y exécute |
| Hadolint | `hadolint --config .hadolint.yaml Dockerfile` (2.15.1) | 0 alerte, y compris au seuil `style` |
| Politique Hadolint | `scripts/ci/check_hadolint_policy.py` (2.15.1) | configuration conforme ; 19 règles d'équipe bloquantes en `error` ; seuil `style` et refus des pragmas effectifs |
| Pinning | `scripts/ci/check_pinning.py` | Dockerfile (sans `ADD`), Compose, `requirements*.txt` (`==`) et actions conformes |
| Dive ≥ 80 % | `dive --ci --ci-config .dive-ci` (0.13.1) | PASS : 99,72 %, 0,50 % d'octets gaspillés |
| Trivy image | gate HIGH/CRITICAL corrigibles (0.75.0) | 0 ; rapport complet : 0 CVE détectée |
| Trivy dépendances | `trivy fs` (détecte `requirements.txt`) | 0 |
| Trivy PostgreSQL | gate HIGH/CRITICAL corrigibles sur l'image Chainguard (0.75.0) | 0 ; rapport complet : 0 CVE détectée |
| Durcissement Compose | `docker inspect`, `/proc/1/status` et `/proc/1/environ` des deux conteneurs, écriture sur `/` et `/app` | `ReadonlyRootfs`, `CapDrop: ALL`, `CapEff=0` et `NoNewPrivs=1` pour `api-python` et `db` ; mot de passe absent de `docker inspect` et de l'environnement de l'API, réexporté par l'entrypoint dans le processus `db` |
| Persistance PostgreSQL | `down` sans `-v` puis `up` | données conservées |
| Utilisateur / shell | `docker image inspect`, `docker run --entrypoint sh` | `65532:65532` ; `sh` introuvable |
| Workflow | `actionlint` 1.7.12 (avec shellcheck) | 0 erreur |
| Services healthy | `docker compose up -d --no-build --wait` avec `API_IMAGE`, identifiants générés et secret `secrets/db_password` en 0644, comme la CI | `api-python` et `db` healthy ; `api-python` exécute l'Image ID audité |
| Tests d'intégration | `pytest -m integration tests/integration` | 3 passed |
| Isolation | connexion à `db:5432` depuis le réseau `frontend` | nom `db` non résolu (`gaierror`) |
| Image seule | `docker run --read-only --cap-drop ALL`, `GET /health` | 200 `{"status":"ok"}` ; `/dbtest` 500 générique |
| Publication | jobs `Release GHCR` + `Pull public + smoke test` | voir le run de release ci-dessus |

Preuves détaillées de la stack ([`evidence/`](evidence/)) :

| Fichier | Contenu |
| --- | --- |
| [`before/`](evidence/before/) | état initial : Flake8, Hadolint, image, paquets, Dive, Trivy |
| [`after/flake8.txt`](evidence/after/flake8.txt) | Flake8 après correction |
| [`after/hadolint.txt`](evidence/after/hadolint.txt) | Hadolint, politique d'équipe rejouée sur des Dockerfiles fautifs, mutations de la configuration, limites |
| [`after/dockerignore.txt`](evidence/after/dockerignore.txt) | fichiers reçus par le build malgré des fichiers parasites |
| [`after/image.txt`](evidence/after/image.txt) | taille, utilisateur, shell, binaires, permissions |
| [`after/dive.txt`](evidence/after/dive.txt) | Dive en mode CI |
| [`after/dive-db.txt`](evidence/after/dive-db.txt) | taille et efficacité Dive de l'image PostgreSQL (mesure, non bloquante en CI) |
| [`after/trivy.txt`](evidence/after/trivy.txt) | Trivy sur l'image finale (toutes sévérités) et gate HIGH/CRITICAL de la CI sur l'archive `docker save` |
| [`after/trivy-db.txt`](evidence/after/trivy-db.txt) | Trivy sur l'image PostgreSQL Chainguard, et gate HIGH/CRITICAL |
| [`after/trivy-deps.txt`](evidence/after/trivy-deps.txt) | Trivy sur `requirements.txt`, et gate HIGH/CRITICAL (renommé : Dependabot lisait l'ancien nom `*requirements*.txt` comme un manifeste pip) |
| [`after/build-cache.txt`](evidence/after/build-cache.txt) | cache des dépendances conservé après modification du code |
| [`after/runtime-compat.txt`](evidence/after/runtime-compat.txt) | même Python, ABI et glibc entre build et image finale |
| [`after/image-run.txt`](evidence/after/image-run.txt) | démarrage en lecture seule |
| [`after/app-functional.txt`](evidence/after/app-functional.txt) | endpoints contre PostgreSQL |
| [`after/compose-hardening.txt`](evidence/after/compose-hardening.txt) | stack Compose durcie : secret absent, healthy, capabilities, lecture seule, isolation réseau, intégration, persistance |

Ces mesures TP1 portent sur le Dockerfile d'avant le TP2 (commit `33e6728`)
et ne sont pas écrasées. Depuis le TP2, `scripts/evidence/regenerate.sh` sans
argument, ou avec `build run scan`, délègue au parcours TP2 (§ 8). Les étapes
TP1 telles que `all` ou `dive-db` restent accessibles : le script extrait la
révision TP1 dans un temporaire, exécute son script historique et conserve
uniquement les preuves régénérées dans un nouveau dossier
`evidence/tp1/replay-*/`, avec un fichier `revision.txt`. Le code de sortie du
parcours historique est conservé, y compris si ses contrôles échouent.

```bash
scripts/evidence/regenerate.sh all          # tous les contrôles historiques TP1
scripts/evidence/regenerate.sh dive-db      # mesure historique PostgreSQL
scripts/evidence/regenerate.sh --tp1 run    # run TP1 explicite ; run seul = TP2
```

Le commit TP1 doit être disponible dans l'historique Git local. Prérequis :
Docker démarré, Dive et Trivy installés, `PYTHON` pointant vers un Python 3.15
avec `requirements-dev.txt`. Les fichiers `flake8.txt` et `hadolint.txt` ne
sont pas régénérés par ce parcours. Le script historique ne lit pas le
répertoire `secrets/` de l'utilisateur ; son secret Compose est temporaire et
ses ressources sont nettoyées même après échec. Le checkout courant et les
preuves versionnées dans `evidence/after/` restent inchangés.

## 8. TP2 — BuildKit, secret et multi-architecture

Répartition : Max a écrit le Dockerfile et [`docker-bake.hcl`](docker-bake.hcl)
(PR #8). JB a adapté les politiques, la CI, la publication et les preuves.
SBOM, Grype et VEX : § 9.

### Build avec Bake

```bash
# Jeton factice, jamais un vrai credential ; secrets/ est exclu de Git et du contexte.
install -d -m 0700 secrets
{ printf 'TP2_'; openssl rand -hex 24; } | tr -d '\n' > secrets/build_token
chmod 0600 secrets/build_token
docker buildx create --name tp2 --driver docker-container --use

docker buildx bake --print app app-ci        # résolution, sans build
docker buildx bake app                       # amd64 + arm64 -> dist/app.oci.tar, sans push
CI_PLATFORM=linux/arm64 TAG=ci-arm64 docker buildx bake app-ci   # une plateforme, chargée dans Docker
```

| Variable | Rôle | Défaut |
| --- | --- | --- |
| `IMAGE`, `TAG` | nom sans tag, tag sans `v` | `flask-api`, `local` |
| `BUILD_SECRET_FILE` | **chemin** du jeton, jamais son contenu | `secrets/build_token` |
| `CI_PLATFORM` | plateforme unique de `app-ci` | `linux/amd64` |
| `CACHE_REF` | cache registre distinct des tags de release ; vide : aucun échange distant | vide |

Un chemin de secret hors du dépôt exige `--allow fs.read=<chemin>` avec
Buildx récent : la CI l'accorde à ce seul fichier. Les anciennes commandes
`docker build .` sans `--secret` échouent désormais, comme prévu.

### Secret de build

Le jeton `package_token` est monté seulement pendant le `RUN` pip, en
`/run/secrets/package_token` (`required=true`, `0400`, uid/gid 65532), et
doit être non vide. Il ne passe ni par `ARG` ni par `ENV`. Le build CI
([`scripts/ci/build_variant.sh`](scripts/ci/build_variant.sh)) prouve, sur un
builder `docker-container` dédié :

- secret absent puis vide : échec, avec `--no-cache` pour qu'une couche en
  cache ne masque pas le contrôle ;
- `secrets/build_token` ignoré par Git, et refusé par le contexte Docker même
  si le fichier existe ;
- jeton absent de l'étape suivante ;
- aucune occurrence exacte du jeton dans l'archive finale, dans l'archive de
  l'étape `builder` et dans les blobs du cache `mode=max` exporté : historique,
  configuration et couches décompressées, ainsi que dans les logs ; le
  détecteur est lui-même testé sur une fuite volontaire ;
- Trivy `--scanners secret` avec une règle dédiée au format du jeton
  ([`trivy-secret.yaml`](scripts/ci/trivy-secret.yaml)) sur les deux
  archives, après contrôle positif sur un fixture fuyant isolé.

Les contrôles affichent succès ou échec et un numéro d'entrée, jamais le
jeton. Les logs bruts du build restent dans un répertoire temporaire privé.
Même après un échec ou une interruption, seuls ceux qui ne contiennent pas le
jeton sont copiés dans les rapports publiés ; un log fuyant est retenu
(marqueur `.withheld`) et fait échouer le job. Le fichier jeton est détruit en
fin de build.

### Caches et limites

- **pip** : montage cache BuildKit sur `PIP_CACHE_DIR=/home/nonroot/.cache/pip`
  (`sharing=locked`), jamais dans une couche. `check_pinning.py --require-tp2`
  exige exactement ce montage et refuse `--no-cache-dir`. Preuve : sur le même
  builder, seule la couche pip est invalidée (commentaire ajouté à une copie
  de `requirements.txt`), et pip réutilise les 18 téléchargements
  (`Using cached`, aucun `Downloading`). `--no-cache` ne convient pas pour
  cette preuve : BuildKit ignore alors aussi le montage cache (vérifié :
  18 téléchargements).
- **Temps de build** (`scripts/evidence/tp2.sh bench`, arm64 natif, builder
  `docker-container` neuf démarré avant la mesure, deux exécutions) :

  | Build | Exécution 1 | Exécution 2 | pip |
  | --- | --- | --- | --- |
  | À froid (aucun cache) | 26,7 s | 27,5 s | 18 `Downloading` |
  | Dépendance modifiée, cache pip conservé | 2,1 s | 1,7 s | 18 `Using cached`, 0 `Downloading` |
  | Même modification, cache pip purgé (`prune --filter type=exec.cachemount`) | 5,3 s | 3,6 s | 18 `Downloading` |

  Seule la couche pip est reconstruite dans les deux derniers cas (images de
  base `CACHED`). Le build à froid est dominé par le pull des images de base ;
  le gain du cache pip croît avec la latence réseau, faible sur ce poste.
- **Couches** : `CACHE_REF` active l'import et l'export registre en `mode=max`
  déclarés dans le HCL. La CI ne l'utilise pas : aucune écriture distante,
  donc aucune PR ou fork ne peut empoisonner un cache de confiance. Preuve :
  export `type=local,mode=max` puis build sur un builder neuf qui réutilise
  les couches (étapes `CACHED`).
- **Limites** : le cache `mode=max` ne transporte pas le contenu des montages
  cache. pip n'est donc pas persistant d'un runner à l'autre, ce qui n'est pas
  un objectif du TP. Un cache registre partagé en CI demanderait des refs par
  architecture et `packages: write` sur le seul job concerné, après
  autorisation.

### Deux architectures, une identité vérifiée

- Runners natifs : `ubuntu-24.04` (amd64) et `ubuntu-24.04-arm` (arm64), avec
  build, intégration Compose (API et PostgreSQL sur la même plateforme) et
  tests HTTP. L'architecture est mesurée **dans** chaque conteneur (`uname`) ;
  l'Image ID exécuté est comparé à celui de l'image construite.
- Dive et Trivy tournent sur amd64 pour les deux archives : les inspecter ne
  demande pas de les exécuter. Tous les rapports complets sont tentés avant
  les gates, et tous les gates s'exécutent avant que le job échoue : une erreur
  de rapport ou un gate rouge ne masque pas les contrôles suivants. Les seuils
  TP1 sont conservés : Dive ≥ 80 %, HIGH/CRITICAL corrigibles bloquants, et
  PostgreSQL scanné pour la même plateforme.
- Chaque variante produit son archive, son SHA256, son Image ID, sa plateforme,
  son commit et son run ([`image_archive.py`](scripts/ci/image_archive.py)).
  Une archive corrompue, permutée, d'une autre architecture ou d'un autre run
  est refusée. La tentative attendue est celle du job de build (output de
  confiance) : un « Re-run failed jobs » des scans ou de la release accepte
  l'artefact de la tentative précédente, jamais une tentative future.

### Publication sans reconstruction

Sur tag `vX.Y.Z` uniquement, après succès des trois agrégateurs
([`publish_index.sh`](scripts/ci/publish_index.sh)) :

1. contrôles SemVer, ascendance `main`, ordre des alias, absence prouvée de
   `X.Y.Z` (une erreur d'authentification ou réseau arrête la release) ;
2. vérification des deux archives contre les outputs des jobs producteurs ;
3. `crane push` de chaque archive vers une référence de staging propre au run ;
   contrôle du config digest, de la plateforme et des DiffIDs après `crane pull` ;
4. index assemblé à partir des **digests** vérifiés, contrôlé (exactement
   amd64 + arm64, sans attestations) ;
5. tags `X.Y.Z`, puis `X.Y`, puis `X` posés sur ce digest d'index, chacun
   vérifié ;
6. pull anonyme et smoke test par tag et par digest sur chaque architecture,
   avec le config digest attendu.

**États partiels et reprise.** Un registre ne permet pas de poser plusieurs
tags de façon atomique. Un échec avant l'étape 5 ne promeut rien : seules des
refs `staging-<run>-<tentative>-*` existent, conservées pour diagnostic. Un
échec pendant l'étape 5 peut laisser `X.Y.Z` publié avec `X.Y` et/ou `X`
encore sur la release précédente. Le job affiche alors le digest de l'index
candidat et celui des trois tags. Reprise :

- **`X.Y.Z` absent** : relancer le job de release (« Re-run failed jobs »). Il
  réutilise les mêmes archives validées ; les nouvelles refs de staging sont
  propres à la tentative.
- **`X.Y.Z` présent sur l'index candidat de ce run**, alias manquants ou
  anciens : ne pas relancer le job, qui refuse à raison une version existante.
  Un mainteneur disposant de `packages: write` vérifie que `vX.Y.Z` est
  toujours la release stable la plus récente. Il pose ensuite chaque alias
  manquant sur ce digest (`crane tag ghcr.io/…@<digest> X.Y`) et le vérifie
  (`crane digest`), puis lance les pulls anonymes de l'étape 6. `X.Y.Z`
  n'est jamais réécrit.
- **`X.Y.Z` présent sur un autre digest** : arrêt. Ne rien écraser ;
  analyser l'origine, puis publier une nouvelle version de correctif.

Le chemin archive → push → index → pull a été validé localement avec un
registre jetable. Aucune image de test n'a été poussée sur GHCR.

### Preuves TP2

[`scripts/evidence/tp2.sh`](scripts/evidence/tp2.sh) (étapes `build run scan bench`)
écrit dans `evidence/tp2/<run>-<arch>/` : environnement (commit, versions
Docker, Buildx, Compose), logs de build, du cache pip et du cache de couches,
métadonnées, intégration. Les mesures TP1 de `evidence/after/` sont conservées.

| Contrôle | Local arm64 (natif) | Local amd64 (émulé) | CI amd64 / arm64 (natifs) | Release |
| --- | --- | --- | --- | --- |
| Secret absent/vide refusé, aucune fuite | ✅ | ✅ | ✅ / ✅ | — |
| Cache pip réutilisé (18 `Using cached`, 0 `Downloading`) | ✅ | ✅ | ✅ / ✅ | — |
| Cache de couches sur builder neuf (6 étapes `CACHED`) | ✅ | ✅ | ✅ / ✅ | — |
| Compose + 3 tests HTTP, architecture et Image ID vérifiés | ✅ | ✅ | ✅ / ✅ | — |
| Dive ≥ 80 % | ✅ 99,74 % | ✅ 99,72 % | ✅ 99,72 % / 99,74 % | — |
| Trivy, toutes sévérités (API, deps, PostgreSQL) | ✅ 0 | ✅ 0 | ✅ 0 / 0 | — |
| Index amd64 + arm64 publié, pulls anonymes | registre jetable | — | — | à vérifier (non exécutée) |

CI : [run 40343481595](https://github.com/maximilianpw/devsecops-max-jb/actions/runs/40343481595)
(PR #10, commit `d5989da`, 2026-10-26), Buildx 0.38.0, BuildKit 0.33.1 ;
les 5 checks requis sont verts, et la publication est sautée hors tag.
Image IDs testés puis scannés : amd64 `sha256:253721ca…`, arm64
`sha256:20d11bce…`. Rapports : artefacts `build-reports-*` et `scan-reports-*`.

Preuves locales : `evidence/tp2/local-1793025514-arm64/` et `evidence/tp2/local-1793025818-amd64/`. Environnement : macOS arm64, Docker 29.5.3 (containerd image store),
Buildx 0.34.1, BuildKit 0.33.1 (builder `docker-container`), le 2026-10-26.
Benchmark : `evidence/tp2/local-1793278412-arm64/` et
`evidence/tp2/local-1793278449-arm64/` (`timings.txt`, logs `bench-*`), Docker
29.8.2, Buildx 0.37.2, BuildKit 0.33.1, le 2026-10-29.

## 9. TP2 — SBOM, Grype et VEX

### Inventaire (SBOM)

Le job de scan de chaque architecture génère l'inventaire depuis l'archive
**vérifiée** (`load_verified_image.sh`), par analyse statique, sans lancer le
conteneur ([`scan_variant.sh`](scripts/ci/scan_variant.sh)) :

```bash
syft scan docker-archive:dist/image.tar \
  -o cyclonedx-json=reports/sbom/sbom.cdx.json \
  -o spdx-json=reports/sbom/sbom.spdx.json
```

Les deux fichiers sont publiés dans l'artefact `sbom-<arch>-<tentative>`
(output `sbom-artifact-id` de `tp2-scan.yaml`), et copiés à la racine du dépôt
pour la release. [`sbom_stats.sh`](scripts/ci/sbom_stats.sh) en extrait les
statistiques (`reports/sbom-stats.txt`) et échoue sur un inventaire vide :

```bash
jq '.components | length' sbom.cdx.json                                   # 1906
jq -r '.components | group_by(.type)[] | "\(.[0].type) \(length)"' sbom.cdx.json
jq '.packages | length' sbom.spdx.json                                    # 40
jq -r '.components[].purl // empty' sbom.cdx.json | sort -u               # 39 PURL
jq -r '[.components[].licenses[]? | .license.id // .license.name // .expression] | unique[]' sbom.cdx.json
jq -r '[.packages[] | .licenseConcluded, .licenseDeclared]
       | map(select(. != null and . != "NOASSERTION")) | unique[]' sbom.spdx.json
```

Résultats (Syft 1.54.1, identiques sur amd64 et arm64 au `arch=` des PURL près) :

| Mesure | CycloneDX | SPDX |
| --- | --- | --- |
| Entrées | 1906 composants : 39 `library`, 1 `operating-system` (Wolfi), 1866 `file` | 40 paquets : les 39 mêmes + l'image racine |
| PURL uniques | 39 : 30 `pkg:apk/wolfi`, 9 `pkg:pypi` | 39 + le `pkg:oci` de l'image |
| Licences distinctes | 13 | 13 (expressions composées entre parenthèses, `LicenseRef-LGPL-with-exceptions`) |

Les écarts viennent du format : CycloneDX range les fichiers catalogués parmi
les composants, SPDX les met dans `files` et ajoute l'image comme paquet.

- Paquets Python : flask 3.1.3, werkzeug 3.1.9, gunicorn 26.2.0,
  psycopg2-binary 2.9.13, jinja2 3.1.6, markupsafe 3.0.4, click 8.5.0,
  itsdangerous 2.2.0, blinker 1.9.0.
- Licences : Apache-2.0, BSD-2-Clause, BSD-3-Clause, MIT, PSF-2.0,
  LGPL-2.1-or-later, GPL-3.0-or-later (dont `WITH GCC-exception-3.1`),
  MPL-2.0 AND MIT, blessing, LGPL with exceptions, et deux expressions
  composées (glibc, outils système). Les licences GPL concernent des paquets
  système Wolfi utilisés comme bibliothèques ou outils, pas le code de l'API.

### Scan du SBOM et gouvernance VEX

Second scan, indépendant de Trivy : Grype 0.120.1 corrèle le SBOM CycloneDX,
sans relire l'image. [`.grype.yaml`](.grype.yaml) porte la politique :

```yaml
only-fixed: true          # seules les failles corrigibles bloquent
fail-on-severity: high    # HIGH et CRITICAL
vex-documents:
  - security.vex.json
```

```bash
grype sbom:reports/sbom/sbom.cdx.json --config .grype.yaml          # gate (code 2 si échec)
GRYPE_FAIL_ON_SEVERITY= grype sbom:reports/sbom/sbom.cdx.json \
  --only-fixed=false -o json --file reports/grype-full.json         # rapport complet
```

Grype charge `.grype.yaml` depuis le répertoire courant : le rapport complet
lève seulement le seuil et `only-fixed`, et garde donc le VEX. Contrôle
négatif : un SBOM contenant `pkg:pypi/werkzeug@2.2.2` fait échouer le gate
(2 HIGH corrigibles, code 2).

Toutes sévérités, sans VEX, Grype trouve une seule faille, sur les deux
architectures :

| CVE | Paquet | Sévérité | Correctif | EPSS |
| --- | --- | --- | --- | --- |
| CVE-2026-114583 | `python-3.15` 3.15.0_git20261017-r4 (apk Wolfi) | Medium | aucun | 0,2 % |

Elle ne bloquerait pas le gate (Medium, sans correctif). Elle est néanmoins
qualifiée dans [`security.vex.json`](security.vex.json) (OpenVEX v0.2.0) pour
ne pas rester un bruit ignoré sans justification :

```
sans VEX : python-3.15  3.15.0_git20261017-r4  apk  CVE-2026-114583  Medium
avec VEX : python-3.15  3.15.0_git20261017-r4  apk  CVE-2026-114583  Medium  (suppressed by VEX)
           ignoredMatches[].appliedIgnoreRules = [{"namespace": "vex", "vex-status": "not_affected"}]
```

L'énoncé vise le PURL du paquet, `pkg:apk/wolfi/python-3.15@3.15.0_git20261017-r4`,
sans qualificatifs. Grype n'applique pas un produit désigné par l'image
(nom, `pkg:oci`, digest) quand il scanne un SBOM ; le PURL du paquet, lui, est
stable d'un run à l'autre et commun aux deux architectures. La version est
contrôlée : `-r3` ne correspond pas.

**Justification technique** (`vulnerable_code_not_in_execute_path`) : la
faille contourne `tarfile.tar_filter`, et seul `tarfile.extractall()` avec
`filter="tar"` permet d'écrire hors du répertoire cible. Le module fait partie
de la bibliothèque standard présente dans l'image, mais aucun fichier Python
de `/app` (app.py, Flask, Werkzeug, gunicorn, psycopg2, Jinja2…) n'importe
`tarfile`. L'API n'expose que `/health`, `/hello` et `/dbtest`, et ne reçoit
ni n'extrait aucune archive. L'image runtime n'a ni pip, ni shell, ni binaire
`tar` ; elle tourne en UID 65532, sur un système de fichiers en lecture seule,
avec `cap_drop: ALL` et `no-new-privileges`.

**Justification métier** : risque accepté. La sévérité est Medium, l'EPSS de
0,2 %, aucun correctif Wolfi n'existe, et le code n'est pas atteignable :
bloquer la livraison ne réduirait aucun risque. L'énoncé est lié à la version
exacte du paquet. Une mise à jour de l'image de base le rend caduc et la CVE
réapparaît dans le rapport complet, ce qui impose une nouvelle revue. Revue au
plus tard le 2026-11-29, ou plus tôt si un correctif paraît ou si l'API
commence à traiter des archives.

## Reproduction locale

Prérequis : Docker avec Compose v2, Buildx (Bake, builder `docker-container`)
et BuildKit, openssl, Python 3.15, Hadolint
2.15.1, Dive 0.13.1, Trivy 0.75.0, Syft 1.54.1, Grype 0.120.1.

```bash
# Qualité et tests unitaires (sans base)
python -m pip install -r requirements.txt -r requirements-dev.txt
flake8 --config=.flake8 app.py test_app.py tests scripts
pytest -m "not integration"

# Gates statiques
hadolint --config .hadolint.yaml Dockerfile
python3 scripts/ci/check_hadolint_policy.py
docker compose config --no-interpolate --format json \
  | python3 scripts/ci/check_pinning.py --compose-json - --require-tp2

# Chaîne TP2 complète d'une architecture (jeton factice éphémère, preuves
# secret/cache, Compose, Dive, Trivy) -> evidence/tp2/<run>-<arch>/
ARCH=arm64 scripts/evidence/tp2.sh build run scan
ARCH=arm64 scripts/evidence/tp2.sh bench   # temps à froid / cache pip / sans cache pip

# Ou build seul (jeton factice : § 8), Dive, Trivy
CI_PLATFORM=linux/amd64 docker buildx bake app-ci   # charge flask-api:local
dive --ci --ci-config .dive-ci flask-api:local
docker save -o image.tar flask-api:local
trivy image --input image.tar --scanners vuln \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1
syft scan docker-archive:image.tar -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
scripts/ci/sbom_stats.sh sbom.cdx.json sbom.spdx.json
grype sbom:sbom.cdx.json --config .grype.yaml

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
