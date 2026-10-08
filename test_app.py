"""Tests unitaires : client Flask en mémoire, sans base de données."""

import pytest

from app import app, read_db_password


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def test_health(client):
    res = client.get("/health")

    assert res.status_code == 200
    assert res.get_json() == {"status": "ok"}


def test_hello(client):
    res = client.get("/hello")

    assert res.status_code == 200
    assert res.get_json() == {"message": "Hello world"}


def test_unknown_route_returns_404(client):
    res = client.get("/does-not-exist")

    assert res.status_code == 404


def test_db_password_read_from_secret_file(tmp_path, monkeypatch):
    secret = tmp_path / "db_password"
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(secret))
    monkeypatch.setenv("DB_PASSWORD", "from-env")

    assert read_db_password() == "from-file"


def test_db_password_falls_back_to_env(monkeypatch):
    monkeypatch.delenv("DB_PASSWORD_FILE", raising=False)
    monkeypatch.setenv("DB_PASSWORD", "from-env")

    assert read_db_password() == "from-env"


def test_db_password_missing_file_fails_fast(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD_FILE", str(tmp_path / "absent"))

    with pytest.raises(FileNotFoundError):
        read_db_password()
