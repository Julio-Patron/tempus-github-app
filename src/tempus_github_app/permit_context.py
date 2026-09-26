"""Per-execution bridge for runtimes whose ActionAdapter accepts only intent.

The runtime invokes this bridge only after signature validation and atomic
consumption. No mutable context is stored on the shared action adapter.
"""

import json
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from .transport import GitHubPermitError, PermitContext


def verified_permit_context(permit_json: str, gate_db: str | None) -> PermitContext:
    """Called exclusively inside the runtime's post-consumption adapter callback."""
    authorization = json.loads(permit_json)["authorization"]
    expires_at = authorization["expires_at"]
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
        permit_json: str,
        gate_db: str | None,
        artifacts: Mapping[str, Any] | None = None,
    ):
        self._adapter = adapter
        self._permit_json = permit_json
        self._gate_db = gate_db
        self._artifacts = dict(artifacts or {})
        self.supported_actions = adapter.supported_actions
        self.unsupported_error_code = adapter.unsupported_error_code

    def execute_action(self, intent: dict[str, Any]):
        context = verified_permit_context(self._permit_json, self._gate_db)
        if self._artifacts:
            return self._adapter.execute_action(
                intent, context=context, artifacts=self._artifacts
            )
        return self._adapter.execute_action(intent, context=context)
