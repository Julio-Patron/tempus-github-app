"""Per-execution bridge for runtimes whose ActionAdapter accepts only intent.

The runtime invokes this bridge only after signature validation and atomic
consumption. No mutable context is stored on the shared action adapter.
"""

import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from .strict_json import loads as loads_strict
from .transport import GitHubPermitError, PermitContext


def authorization_from_verified(verified: Any) -> dict[str, Any]:
    """Return the authorization object the core verifier already produced.

    ``verify_and_consume_permit`` returns that object as JSON text (or, if a future
    runtime returns the dict itself, that same dict). This is not a parse of the
    original permit.
    """
    if isinstance(verified, (str, bytes, bytearray)):
        parsed = loads_strict(verified)
    elif isinstance(verified, dict):
        return verified
    else:
        raise GitHubPermitError("Verified authorization is not an object")
    if not isinstance(parsed, dict):
        raise GitHubPermitError("Verified authorization is not an object")
    return parsed


class VerifiedPermitSource:
    """Observe the authorization object returned by the core verifier.

    Repeated keys are rejected before the core parser can keep the last one. The
    value of that check is discarded: the context reads only the verified object.
    """

    def __init__(self, executor: Any):
        self._executor = executor
        self.authorization: dict[str, Any] | None = None

    def verify_and_consume_permit(self, permit_json: str) -> Any:
        self.authorization = None
        loads_strict(permit_json)
        verified = self._executor.verify_and_consume_permit(permit_json)
        self.authorization = authorization_from_verified(verified)
        return verified

    def __getattr__(self, name: str) -> Any:
        return getattr(self._executor, name)


def verified_permit_context(
    authorization: Mapping[str, Any], gate_db: str | None
) -> PermitContext:
    """Called exclusively inside the runtime's post-consumption adapter callback.

    ``authorization`` must be the object the verifier returned. Permit text is refused
    so this function cannot take a second reading of the signed bytes.
    """
    if not isinstance(authorization, Mapping):
        raise GitHubPermitError("Permit context requires the verified authorization object")
    try:
        expires_at = authorization["expires_at"]
    except (KeyError, TypeError) as exc:
        raise GitHubPermitError("Invalid signed permit expiry") from exc
    if type(expires_at) is not int or expires_at <= 0:
        raise GitHubPermitError("Invalid signed permit expiry")
    # Tempus timestamps are integer microseconds; transport uses UNIX seconds.
    deadline = expires_at / 1_000_000
    if gate_db is None:
        return PermitContext(deadline)
    authorization_id = authorization["authorization_id"]
    agent_id = authorization["agent_id"]
    uri = Path(gate_db).resolve().as_uri() + "?mode=ro"

    def check_validity() -> bool:
        if time.time() >= deadline:
            return False
        try:
            # A fresh connection observes revocations committed during sleep.
            # mode=ro never creates a missing DB; timeout=0 fails closed on locks.
            with closing(sqlite3.connect(uri, uri=True, timeout=0)) as connection:
                denied = connection.execute(
                    "SELECT EXISTS(SELECT 1 FROM revoked_authorizations WHERE authorization_id = ?) "
                    "OR EXISTS(SELECT 1 FROM identity_lifecycle_events "
                    "WHERE public_key = ? AND event_type = 'REVOKE') "
                    "OR EXISTS(SELECT 1 FROM action_outcomes WHERE authorization_id = ?)",
                    (authorization_id, agent_id, authorization_id),
                ).fetchone()[0]
            return denied == 0 and time.time() < deadline
        except (sqlite3.Error, OSError):
            return False

    return PermitContext(deadline, check_validity)


class PermitBoundActionAdapter:
    """Bind one immutable permit (and its artifacts) to one invocation of ExecutorRuntime.

    Artifacts such as a git bundle are untrusted until the adapter matches them
    against digests inside the signed intent.
    """

    def __init__(
        self,
        adapter: Any,
        verified_permits: VerifiedPermitSource,
        gate_db: str | None,
        artifacts: Mapping[str, Any] | None = None,
    ):
        self._adapter = adapter
        self._verified_permits = verified_permits
        self._gate_db = gate_db
        self._artifacts = dict(artifacts or {})
        self.supported_actions = adapter.supported_actions
        self.unsupported_error_code = adapter.unsupported_error_code

    def execute_action(self, intent: dict[str, Any]):
        authorization = self._verified_permits.authorization
        if not isinstance(authorization, dict):
            raise GitHubPermitError("Permit was not verified")
        context = verified_permit_context(authorization, self._gate_db)
        if self._artifacts:
            return self._adapter.execute_action(
                intent, context=context, artifacts=self._artifacts
            )
        return self._adapter.execute_action(intent, context=context)
