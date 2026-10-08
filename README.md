# API Flask / PostgreSQL durcie

Une API Flask reliée à une base PostgreSQL, durcie de bout en bout : code conforme à Flake8, dépendances sans CVE connue, image sans shell ni root, Compose isolé, et un pipeline GitHub Actions qui bloque tout écart avant de publier l'image sur GHCR.

Les mesures ont été faites sur des images `linux/amd64`, l'architecture des runners GitHub.

## Architecture

| Endpoint | Réponse |
| --- | --- |
| `GET /health` | 200 `{"status":"ok"}` |
| `GET /hello` | 200 `{"message":"Hello world"}` |
| `GET /dbtest` | 200 `{"db_connection":"successful"}` si `SELECT 1` passe |

L'API écoute sur le port 5000 et lit `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` et `DB_PASSWORD`.

Compose lance deux services :

| Service | Image | Réseaux | Port publié |
| --- | --- | --- | --- |
| `api-python` | construite depuis le `Dockerfile` | `frontend`, `backend` | 5000 |
| `db` | Chainguard Postgres 18.6, fixée par digest | `backend` | aucun |

Le réseau `backend` est interne : la base n'a aucun accès vers l'extérieur et n'est joignable que par l'API. Le port 5432 n'est plus publié sur l'hôte. Les données sont dans le volume `db-data-test`.

## 1. Packages GHCR

_À compléter après la première publication : URL des packages et commandes `docker pull` avec tag SemVer._

## 2. Avant / après

Image de l'API :

| | Avant | Après |
| --- | --- | --- |
| Image de base | `python:3.10-slim` | Chainguard Python 3.14.8, fixée par digest |
| Poids | 148,2 Mo | 98,3 Mo |
| Utilisateur | root (uid 0) | nonroot (uid 65532) |
| Shell | oui (`sh`, `bash`) | non |
| CVE Trivy | 185 (47 HIGH, 0 CRITICAL, 20 corrigibles) | 0 |
| Efficience Dive | 97,4 % | 99,8 % |

Image PostgreSQL :

| | Avant | Après |
| --- | --- | --- |
| Image | `postgres:14-alpine` (tag mouvant) | Chainguard Postgres 18.6, fixée par digest |
| Poids | 290,6 Mo | 379,4 Mo |
| Utilisateur du serveur | postgres (uid 70) | postgres (uid 70) |
| Shell | oui (`sh`, `bash`, busybox) | oui (`sh`, `bash`, busybox) |
| Gestionnaire de paquets | apk | aucun |
| CVE Trivy | 47 (1 CRITICAL, 21 HIGH, toutes corrigibles) | 0 |
| Efficience Dive | 99,9 % | 99,9 % |

Le gain porte sur les CVE et l'épinglage. L'image Chainguard est plus lourde et garde bash : son script de démarrage en a besoin. Dans les deux cas, ce script démarre en root, prépare le dossier de données, puis lance PostgreSQL sous l'utilisateur `postgres`.

## 3. Images de base

Le Dockerfile a deux étages :

- `cgr.dev/chainguard/python:latest-dev` installe les dépendances. Il contient pip et un shell, et il est jeté à la fin du build.
- `cgr.dev/chainguard/python:latest` est l'image finale. Elle ne contient que Python, les dépendances et `app.py` : ni shell, ni pip, ni compilateur.

Pourquoi Chainguard : les deux images viennent de la même distribution, avec la même version de Python. Les dépendances installées dans le premier étage fonctionnent donc telles quelles dans le second. Trivy n'y trouve aucune CVE, et la même famille existe pour PostgreSQL.

Immuabilité : Chainguard ne publie gratuitement que les tags `latest` et `latest-dev`, qui changent tous les jours. Les images sont donc référencées par digest SHA256 :

| Étage | Image | Digest |
| --- | --- | --- |
| build | `python:latest-dev` (Python 3.14.8, 2026-10-08) | `sha256:894aed3297d91283e1fc4c542f5374a4b5f3726134fda7c94eaa539342be1e05` |
| final | `python:latest` (Python 3.14.8, 2026-10-08) | `sha256:b6248c85ba9b97e1e61b30197f309cc4d21661f889fefa5268f0a7bc530dad46` |

Reproductibilité : chaque paquet de `requirements.txt` est fixé à une version exacte. Le venv est créé sans pip, ce qui laisse pip hors de l'image finale. Le manifeste est copié avant le code, donc modifier `app.py` ne relance pas l'installation des dépendances. L'API tourne sous le compte `nonroot` (uid 65532).

## 4. Healthchecks sans shell

L'image de l'API n'a pas de shell. Un healthcheck écrit sous forme de texte (`test: "curl ..."` ou `CMD-SHELL`) passe par `/bin/sh` et échoue donc tout de suite. Les deux sondes sont écrites sous forme de liste : Docker lance directement le programme, sans shell.

API : le Python de l'image appelle `/health` avec sa bibliothèque standard. Pas besoin de curl.

```yaml
test: ["CMD", "/app/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"]
```

Si la réponse n'est pas un succès ou n'arrive pas dans les 3 secondes, Python lève une exception et sort avec le code 1 : le conteneur est marqué en échec.

PostgreSQL : `pg_isready`, l'outil fourni avec PostgreSQL, à son chemin réel dans l'image Chainguard.

```yaml
test: ["CMD", "/usr/bin/pg_isready", "-h", "127.0.0.1", "-U", "testuser", "-d", "testdb"]
```

`-h 127.0.0.1` force une connexion TCP. Pendant l'initialisation, PostgreSQL tourne un moment en local seulement, sans écouter le réseau. Sans cette option, la sonde pourrait répondre « prêt » trop tôt.

Ordre de démarrage : `depends_on` avec `condition: service_healthy`. L'API ne démarre qu'une fois la base déclarée saine.

## 5. Remédiations

### Flake8

Avec le `.flake8` fourni, `app.py` passe sans erreur. Les seules violations présentes sont ignorées par cette configuration : 4 × E302, W293 et W391. Aucune correction n'était nécessaire, et `.flake8` n'a pas été modifié.

### Vulnérabilités du `requirements.txt` d'origine

| Paquet | Version | CVE | Nouvelle version |
| --- | --- | --- | --- |
| Werkzeug | 2.3.3 | CVE-2024-34069 (HIGH) ; CVE-2023-46136, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 (MEDIUM) | 3.1.9 |
| Flask | 2.3.2 | CVE-2026-27205 (LOW) | 3.1.3 |
| pytest | 7.4.0 | CVE-2025-71176 (MEDIUM) | 9.1.1 |
| psycopg2-binary | non fixée | aucune | 2.9.13 |

- **Werkzeug 3.1.9** : première version qui corrige les 8 CVE.
- **Flask 3.1.3** : corrige sa CVE, et Werkzeug 3.1 exige Flask 3.1.
- **pytest 9.1.1** : dernière version, corrige sa CVE.
- **psycopg2-binary 2.9.13** : pas de CVE, mais la version n'était pas fixée. Elle l'est maintenant pour que chaque build installe la même.

Vérifié sous Compose avec Chainguard Postgres 18.6 : `/health`, `/hello` et `/dbtest` répondent correctement, et les 3 tests de `test_app.py` passent.

Passer de PostgreSQL 14 à 18 change le format des données : un ancien volume `db-data-test` doit être supprimé (`docker compose down -v`) avant le premier démarrage.

## 6. Sécurisation de la chaîne CI/CD

_À compléter._

## 7. Preuves d'exécution

Flake8 :

```
$ flake8 --config=.flake8 app.py
$ echo $?
0
```

Hadolint :

```
$ hadolint --config .hadolint.yaml Dockerfile
$ echo $?
0
```

Dive :

```
$ dive --ci --lowestEfficiency=0.8 --highestWastedBytes=disabled --highestUserWastedPercent=disabled flask-api:local
  efficiency: 99.7592 %
  PASS: lowestEfficiency
Result:PASS [Total:3] [Passed:1] [Failed:0] [Warn:0] [Skipped:2]
```

Trivy :

```
$ trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 flask-api:local
Report Summary
│ Target                                                                          │ Type       │ Vulnerabilities │
│ flask-api:local (wolfi 20230201)                                                │ wolfi      │        0        │
│ app/venv/lib/python3.14/site-packages/flask-3.1.3.dist-info/METADATA            │ python-pkg │        0        │
│ app/venv/lib/python3.14/site-packages/psycopg2_binary-2.9.13.dist-info/METADATA │ python-pkg │        0        │
│ app/venv/lib/python3.14/site-packages/pytest-9.1.1.dist-info/METADATA           │ python-pkg │        0        │
│ app/venv/lib/python3.14/site-packages/werkzeug-3.1.9.dist-info/METADATA         │ python-pkg │        0        │
…  (13 paquets Python, 0 vulnérabilité chacun)
$ echo $?
0
```

Utilisateur et shell :

```
$ docker run --rm --entrypoint /bin/sh flask-api:local
… exec: "/bin/sh": stat /bin/sh: no such file or directory
$ docker run --rm --entrypoint /app/venv/bin/python flask-api:local -c 'import os; print(os.getuid(), os.getgid())'
65532 65532
```

Compose, services sains :

```
$ docker compose up -d --build --wait --wait-timeout 120
…
 Container devsecops-tp12-db-1 Healthy
 Container devsecops-tp12-api-python-1 Healthy
$ docker compose ps
SERVICE      STATUS                    PORTS
api-python   Up 5 seconds (healthy)    0.0.0.0:5000->5000/tcp, [::]:5000->5000/tcp
db           Up 11 seconds (healthy)
```

Tests d'intégration, lancés dans le réseau Compose :

```
$ docker compose run --rm --no-deps -T -e PYTHONPATH=/app -v "$PWD/test_app.py":/tests/test_app.py:ro --entrypoint /app/venv/bin/python api-python -m pytest -q -p no:cacheprovider /tests/test_app.py
3 passed, 1 warning in 0.10s
```

Isolation :

```
$ nc -z -w 2 127.0.0.1 5432 && echo ouvert || echo fermé
fermé
$ docker top $(docker compose ps -q api-python) -eo user,pid,args
USER     PID       COMMAND
65532    1416944   /app/venv/bin/python /app/app.py
$ docker top $(docker compose ps -q db) -eo user,pid,args
USER     PID       COMMAND
70       1416810   postgres
70       1416892   postgres: io worker 0
…
```

_À compléter : publication GHCR._
