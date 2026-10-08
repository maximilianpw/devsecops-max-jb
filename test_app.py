"""Tests unitaires : client Flask en mémoire, sans base de données."""

import pytest

from app import app


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
