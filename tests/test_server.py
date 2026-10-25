from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from starlette.testclient import TestClient

from tempus_github_app.server import create_webhook_app
from tempus_github_app.webhook import GitHubWebhookHandler


def _sign(secret: str, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


@pytest.fixture
def test_secret() -> str:
    return "webhook-secret-123"


@pytest.fixture
def client(test_secret: str) -> TestClient:
    handler = GitHubWebhookHandler(test_secret)

    @handler.on("issues")
    def on_issue(event: str, payload: dict):
        return f"issue:{payload.get('action')}"

    app = create_webhook_app(webhook_secret=test_secret, handler=handler)
    return TestClient(app)


def test_healthz_endpoint(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "tempus-github-app-server",
    }


def test_webhook_ping_event(client: TestClient, test_secret: str):
    body = b'{"zen":"Keep it logically awesome."}'
    sig = _sign(test_secret, body)
    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "pong"


def test_webhook_valid_signature_and_handler(client: TestClient, test_secret: str):
    data = {"action": "opened", "issue": {"number": 42, "title": "Test Issue"}}
    body = json.dumps(data).encode("utf-8")
    sig = _sign(test_secret, body)

    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "accepted"
    assert res["event"] == "issues"
    assert res["handled"] is True
    assert res["result"] == "issue:opened"


def test_webhook_invalid_signature_rejected(client: TestClient):
    body = b'{"action":"opened"}'
    response = client.post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        },
    )
    assert response.status_code == 401


def test_webhook_missing_signature_rejected(client: TestClient):
    body = b'{"action":"opened"}'
    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues"},
    )
    assert response.status_code == 401


def test_webhook_duplicate_json_key_rejected(client: TestClient, test_secret: str):
    body = b'{"action":"opened","action":"closed"}'
    sig = _sign(test_secret, body)
    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 400
    assert "DUPLICATE_JSON_KEY" in response.json()["detail"]


def test_webhook_malformed_json_rejected(client: TestClient, test_secret: str):
    body = b"not-valid-json"
    sig = _sign(test_secret, body)
    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 400


def test_webhook_unhandled_error_returns_generic_500(test_secret: str):
    handler = GitHubWebhookHandler(test_secret)

    @handler.on("issues")
    def on_issue(event: str, payload: dict):
        raise RuntimeError("Sensitive internal database error")

    app = create_webhook_app(webhook_secret=test_secret, handler=handler)
    client = TestClient(app, raise_server_exceptions=False)

    body = b'{"action":"opened"}'
    sig = _sign(test_secret, body)
    response = client.post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "issues", "X-Hub-Signature-256": sig},
    )
    assert response.status_code == 500
    assert response.json()["detail"] == "Error handling event"
    assert "Sensitive internal database error" not in response.text
