"""Verify the static diagnostic endpoint and restricted route surface."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_healthz_returns_ok(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/", "/missing", "/healthz/missing"])
def test_undefined_endpoints_return_404(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize(
    "path", ["/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"]
)
def test_documentation_endpoints_are_unavailable(client, path):
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_healthz_rejects_other_methods(client, method):
    assert client.request(method, "/healthz").status_code == 405
