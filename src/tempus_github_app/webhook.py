"""GitHub App webhook verification and event dispatching."""

import hashlib
import hmac
from collections.abc import Callable
from typing import Any

from .strict_json import loads as loads_strict


class WebhookVerificationError(ValueError):
    """Raised when GitHub webhook signature verification fails."""


def verify_webhook_signature(
    payload_bytes: bytes, secret: str, signature_header: str | None
) -> bool:
    """Verify that the webhook payload was signed by GitHub using the shared secret.

    GitHub passes the signature in the 'X-Hub-Signature-256' header prefixed with 'sha256='.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_signature = signature_header[len("sha256=") :]
    mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
    computed_signature = mac.hexdigest()

    return hmac.compare_digest(computed_signature, expected_signature)


class GitHubWebhookHandler:
    """Dispatches verified GitHub webhook events to registered action handlers."""

    def __init__(self, webhook_secret: str):
        self._webhook_secret = webhook_secret
        self._handlers: dict[str, Callable[[str, dict[str, Any]], Any]] = {}

    def on(self, event_type: str):
        """Decorator to register a handler for a specific GitHub event type (e.g., 'issues')."""

        def decorator(func: Callable[[str, dict[str, Any]], Any]):
            self._handlers[event_type] = func
            return func

        return decorator

    def handle(
        self,
        event_name: str,
        payload_bytes: bytes,
        signature_header: str | None,
    ) -> Any:
        """Verify signature and dispatch event to handler."""
        if not verify_webhook_signature(
            payload_bytes, self._webhook_secret, signature_header
        ):
            raise WebhookVerificationError("Invalid or missing webhook signature")

        payload = loads_strict(payload_bytes)
        handler = self._handlers.get(event_name)
        if handler:
            return handler(event_name, payload)
        return None
