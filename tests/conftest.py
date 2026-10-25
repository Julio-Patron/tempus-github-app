from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tempus_ddb import TempusDDB, gen_keys

from tempus_github_app.transport import PermitContext


@pytest.fixture
def app_key(tmp_path: Path) -> tuple[Path, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "app.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, key


class MockAppTransport:
    """Mock transport handling both GitHub App access token minting and API calls."""

    def __init__(self, now: list[float] | None = None) -> None:
        self.now = now if now is not None else [time.time()]
        self.calls: list[tuple[str, str, dict[str, str], dict[str, Any]]] = []
        self.failure: Exception | None = None
        self.token = "installation-test-credential"
        self.contexts: list[PermitContext | None] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        context: PermitContext | None = None,
    ) -> dict[str, Any]:
        self.calls.append((method, url, headers, payload))
        self.contexts.append(context)
        if self.failure:
            raise self.failure

        if "access_tokens" in url:
            return {
                "token": self.token,
                "expires_at": datetime.fromtimestamp(
                    self.now[0] + 3600, timezone.utc
                ).isoformat(),
            }

        # Response for issues or pull requests
        if "/issues" in url:
            return {
                "id": 101,
                "number": 1,
                "state": "open",
                "html_url": "https://github.com/acme/widget/issues/1",
                "url": "https://api.github.com/repos/acme/widget/issues/1",
            }
        if "/pulls" in url:
            return {
                "id": 202,
                "number": 2,
                "state": "open",
                "html_url": "https://github.com/acme/widget/pull/2",
                "url": "https://api.github.com/repos/acme/widget/pulls/2",
            }

        return {"status": "ok"}


def setup_gate_and_agents(
    tmp_path: Path, tenant_id: str = "test-tenant"
) -> dict[str, Any]:
    """Initialize a Tempus Gate, agent, and executor with Ed25519 keys."""
    gate_db = tmp_path / "gate.db"
    exec_db = tmp_path / "executor.db"
    gate_keyfile = tmp_path / "gate.keys.json"
    agent_keyfile = tmp_path / "agent.keys.json"
    exec_keyfile = tmp_path / "executor.keys.json"

    gen_keys(str(gate_keyfile))
    gen_keys(str(agent_keyfile))
    gen_keys(str(exec_keyfile))

    gate = TempusDDB(str(gate_db), str(gate_keyfile))
    # 0.5.3 seeds an allow-all baseline. Later cores refuse actions until a policy
    # is installed; the dev helper is the one the core publishes for tests.
    if hasattr(gate, "install_allow_all_dev_policy"):
        gate.install_allow_all_dev_policy()

    with gate_keyfile.open(encoding="utf-8") as f:
        gate_id = json.load(f)["public_key"]
    with agent_keyfile.open(encoding="utf-8") as f:
        agent_id = json.load(f)["public_key"]
    with exec_keyfile.open(encoding="utf-8") as f:
        exec_id = json.load(f)["public_key"]

    gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
    gate.register_agent(agent_id, "test-agent", "{}")
    gate.register_agent(exec_id, "test-executor", "{}")

    return {
        "gate": gate,
        "gate_db": str(gate_db),
        "gate_keyfile": str(gate_keyfile),
        "gate_id": gate_id,
        "agent_keyfile": str(agent_keyfile),
        "agent_id": agent_id,
        "exec_db": str(exec_db),
        "exec_keyfile": str(exec_keyfile),
        "exec_id": exec_id,
        "tenant_id": tenant_id,
    }
