from __future__ import annotations

import time

import pytest

from tempus_github_app.credentials import GitHubAppCredentials
from tempus_github_app.executor import GitHubAppActionAdapter
from tests.conftest import MockAppTransport


def test_auth_failure_does_not_write_or_leak_credentials(app_key):
    now = [time.time()]
    transport = MockAppTransport(now)
    transport.failure = RuntimeError("private-secret-value")
    credentials = GitHubAppCredentials(
        "Iv1.test",
        str(app_key[0]),
        42,
        "acme/widget",
        transport=transport,
        clock=lambda: now[0],
    )
    adapter = GitHubAppActionAdapter(credentials=credentials, transport=transport)
    result = adapter.execute_action(
        {
            "action_type": "github.create_issue",
            "resource": "acme/widget",
            "input": {"title": "test"},
        }
    )
    assert result.status == "FAILED"
    assert result.payload == {"error_code": "TEMPUS_GITHUB_BINDING_REJECTED"}
    assert len(transport.calls) == 1
    assert transport.calls[0][1].endswith("/access_tokens")


def test_action_adapter_executes_issue_creation(app_key):
    now = [time.time()]
    auth_transport = MockAppTransport(now)
    credentials = GitHubAppCredentials(
        "Iv1.test",
        str(app_key[0]),
        42,
        "acme/widget",
        transport=auth_transport,
        clock=lambda: now[0],
    )

    class CombinedTransport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, headers, payload):
            self.calls.append((method, url, headers, payload))
            if "access_tokens" in url:
                return auth_transport.request(method, url, headers, payload)
            assert headers["Authorization"] == f"Bearer {auth_transport.token}"
            return {"id": 101, "number": 1, "html_url": "https://github.com/acme/widget/issues/1"}

    combined = CombinedTransport()
    adapter = GitHubAppActionAdapter(credentials=credentials, transport=combined)
    result = adapter.execute_action(
        {
            "action_type": "github.create_issue",
            "resource": "acme/widget",
            "input": {"title": "Bug report", "body": "Details here"},
        }
    )
    assert result.status == "SUCCEEDED"
    assert result.payload["number"] == 1
    assert result.payload["resource"] == "acme/widget"


def test_executor_adapter_rejects_gate_db_if_runtime_lacks_support(app_key, monkeypatch, tmp_path):
    import tempus_ddb.executor_runtime

    from tempus_github_app.executor import GitHubAppExecutorAdapter, GitHubExecutorError

    credentials = GitHubAppCredentials(
        "Iv1.test",
        str(app_key[0]),
        42,
        "acme/widget",
    )

    # Create signature without gate_db
    def mock_init(self, executor_db, executor_keyfile, trusted_gate_id, trusted_tenant_id, executor_pool_size=8):
        pass

    monkeypatch.setattr(tempus_ddb.executor_runtime.ExecutorRuntime, "__init__", mock_init)

    with pytest.raises(GitHubExecutorError, match="gate_db is configured for revocation verification, but the underlying ExecutorRuntime does not support it"):
        GitHubAppExecutorAdapter(
            executor_db=str(tmp_path / "exec.db"),
            executor_keyfile=str(tmp_path / "exec.keys.json"),
            trusted_gate_id="gate-id",
            trusted_tenant_id="tenant-id",
            credentials=credentials,
            gate_db=str(tmp_path / "gate.db"),
        )
