"""Tests d'intégration HTTP contre l'API conteneurisée et PostgreSQL.

La stack doit être démarrée au préalable :
    docker compose up -d --no-build --wait --wait-timeout 120
L'URL cible est configurable via API_BASE_URL (défaut : http://127.0.0.1:5000).
"""

import json
import os
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.integration

BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
TIMEOUT_SECONDS = float(os.getenv("API_TIMEOUT_SECONDS", "5"))


def get_json(path):
    """Retourne (code HTTP, corps JSON) sans lever d'exception sur 4xx/5xx."""
    request = urllib.request.Request(
        f"{BASE_URL}{path}", headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as res:
            status, body = res.status, res.read()
    except urllib.error.HTTPError as err:
        status, body = err.code, err.read()
    return status, json.loads(body)


def test_health():
    assert get_json("/health") == (200, {"status": "ok"})


def test_hello():
    assert get_json("/hello") == (200, {"message": "Hello world"})


def test_dbtest_reaches_postgresql():
    status, body = get_json("/dbtest")

    assert status == 200, body
    assert body == {"db_connection": "successful"}
