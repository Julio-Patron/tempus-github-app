import hashlib
import hmac
import json

import pytest

from tempus_github_app.webhook import (
    GitHubWebhookHandler,
    WebhookVerificationError,
    verify_webhook_signature,
)


def test_verify_webhook_signature():
    secret = "my-secret"
    payload = b'{"action":"opened","issue":{"number":1}}'
    mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    header = f"sha256={mac}"

    assert verify_webhook_signature(payload, secret, header) is True
    assert verify_webhook_signature(payload, "wrong-secret", header) is False
    assert verify_webhook_signature(payload, secret, "sha256=invalidhex") is False
    assert verify_webhook_signature(payload, secret, None) is False


def test_webhook_handler_dispatch():
    secret = "webhook-key"
    handler = GitHubWebhookHandler(secret)

    received = []

    @handler.on("issues")
    def handle_issue(event, payload):
        received.append((event, payload["issue"]["title"]))
        return "OK"

    payload_data = {"action": "opened", "issue": {"title": "Test Title"}}
    payload_bytes = json.dumps(payload_data).encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    header = f"sha256={mac}"

    result = handler.handle("issues", payload_bytes, header)
    assert result == "OK"
    assert received == [("issues", "Test Title")]

    with pytest.raises(WebhookVerificationError):
        handler.handle("issues", payload_bytes, "sha256=bad")


def test_duplicate_json_key_is_rejected():
    secret = "webhook-key"
    handler = GitHubWebhookHandler(secret)
    called = []

    @handler.on("issues")
    def handle_issue(event, payload):
        called.append(payload)

    payload_bytes = b'{"action":"opened","action":"closed","issue":{"title":"x","title":"y"}}'
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    with pytest.raises(json.JSONDecodeError, match="DUPLICATE_JSON_KEY"):
        handler.handle("issues", payload_bytes, f"sha256={mac}")
    assert called == []
