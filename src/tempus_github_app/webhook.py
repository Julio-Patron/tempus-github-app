"""GitHub App webhook verification and event dispatching."""

import hashlib
import hmac
import time
from collections.abc import Callable
from typing import Any

from .strict_json import loads as loads_strict

# GitHub redelivers the same X-GitHub-Delivery for some time. Keep it long enough
# that a replay inside that window is rejected, and short enough to forget it after.
WEBHOOK_DELIVERY_TTL_SECONDS = 24 * 60 * 60


class WebhookVerificationError(ValueError):
    """Raised when GitHub webhook signature verification fails."""


class DeliveryLog:
    """Remember X-GitHub-Delivery values until their TTL elapses."""

    def __init__(
        self,
        ttl_seconds: float = WEBHOOK_DELIVERY_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        if type(ttl_seconds) not in (int, float) or ttl_seconds <= 0:
            raise ValueError("delivery TTL must be positive")
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._seen: dict[str, float] = {}

    def claim(self, delivery_id: str | None) -> None:
        if not isinstance(delivery_id, str) or not delivery_id.strip():
            raise WebhookVerificationError("Missing X-GitHub-Delivery")
        now = self._clock()
        expired = [key for key, until in self._seen.items() if until <= now]
        for key in expired:
            del self._seen[key]
        key = delivery_id.strip()
        until = self._seen.get(key)
        if until is not None and until > now:
            raise WebhookVerificationError("Duplicate X-GitHub-Delivery")
        self._seen[key] = now + self._ttl


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

    def __init__(
        self,
        webhook_secret: str,
        *,
        delivery_ttl_seconds: float = WEBHOOK_DELIVERY_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ):
        self._webhook_secret = webhook_secret
        self._handlers: dict[str, Callable[[str, dict[str, Any]], Any]] = {}
        self._deliveries = DeliveryLog(delivery_ttl_seconds, clock)

    def on(self, event_type: str):
        """Decorator to register a handler for a specific GitHub event type (e.g., 'issues')."""

        def decorator(func: Callable[[str, dict[str, Any]], Any]):
            self._handlers[event_type] = func
            return func

        return decorator

    def accept_delivery(self, delivery_id: str | None) -> None:
        """Reject a missing or already seen X-GitHub-Delivery within the TTL."""
        self._deliveries.claim(delivery_id)

    def handle(
        self,
        event_name: str,
        payload_bytes: bytes,
        signature_header: str | None,
        delivery_id: str | None = None,
    ) -> Any:
        """Verify signature and dispatch event to handler."""
        if not verify_webhook_signature(
            payload_bytes, self._webhook_secret, signature_header
        ):
            raise WebhookVerificationError("Invalid or missing webhook signature")

        payload = loads_strict(payload_bytes)
        # Claim only after the payload parses, and before the handler runs.
        self.accept_delivery(delivery_id)
        handler = self._handlers.get(event_name)
        if handler:
            return handler(event_name, payload)
        return None
