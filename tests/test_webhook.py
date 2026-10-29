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

    result = handler.handle("issues", payload_bytes, header, delivery_id="delivery-1")
    assert result == "OK"
    assert received == [("issues", "Test Title")]

    with pytest.raises(WebhookVerificationError):
        handler.handle("issues", payload_bytes, "sha256=bad", delivery_id="delivery-2")


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
        handler.handle("issues", payload_bytes, f"sha256={mac}", delivery_id="delivery-dup")
    assert called == []


def _signed(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def test_duplicate_delivery_is_rejected_until_ttl():
    secret = "webhook-key"
    now = [1_000.0]
    handler = GitHubWebhookHandler(secret, delivery_ttl_seconds=10, clock=lambda: now[0])
    seen = []

    @handler.on("issues")
    def handle_issue(event, payload):
        seen.append(payload["n"])
        return "OK"

    body = b'{"n":1}'
    header = _signed(secret, body)
    assert handler.handle("issues", body, header, delivery_id="abc") == "OK"
    with pytest.raises(WebhookVerificationError, match="Duplicate"):
        handler.handle("issues", body, header, delivery_id="abc")
    assert seen == [1]
    other = b'{"n":2}'
    assert handler.handle("issues", other, _signed(secret, other), delivery_id="def") == "OK"
    now[0] = 1_010.0
    again = b'{"n":3}'
    assert handler.handle("issues", again, _signed(secret, again), delivery_id="abc") == "OK"
    assert seen == [1, 2, 3]


@pytest.mark.parametrize("delivery_id", [None, "", "   "])
def test_missing_delivery_id_is_rejected(delivery_id):
    secret = "webhook-key"
    handler = GitHubWebhookHandler(secret)
    body = b'{"n":1}'
    with pytest.raises(WebhookVerificationError, match="Missing"):
        handler.handle("issues", body, _signed(secret, body), delivery_id=delivery_id)
