import json
import time
from unittest.mock import Mock

import pytest
from tempus_ddb.executor_runtime import AmbiguousTransportError

from tempus_github_app.credentials import GitHubAppCredentials
from tempus_github_app.executor import GitHubAppActionAdapter, GitHubAppExecutorAdapter
from tempus_github_app.transport import GitHubAPIError, GitHubExecutorError
from tests.conftest import MockAppTransport, setup_gate_and_agents

SHA = "aB" * 20
INPUT = {"pull_number": 7, "sha": SHA, "merge_method": "squash"}


def intent(inputs=None):
    return {"action_type": "github.merge_pull_request", "resource": "acme/widget",
            "input": dict(INPUT if inputs is None else inputs)}


@pytest.mark.parametrize("method", ["merge", "squash", "rebase"])
def test_merge_request_and_sanitized_response(method):
    credentials, transport = Mock(), Mock()
    credentials.token_for.return_value = "secret"
    transport.request.return_value = {"merged": True, "sha": "c" * 40,
                                      "message": "secret", "token": "secret"}
    adapter = GitHubAppActionAdapter(credentials, transport=transport)
    inputs = {**INPUT, "merge_method": method, "commit_title": "Title", "commit_message": "Body"}
    result = adapter.execute_action(intent(inputs))
    assert result.status == "SUCCEEDED"
    assert result.payload == {"action_type": "github.merge_pull_request", "resource": "acme/widget",
                              "merged": True, "sha": "c" * 40}
    args = transport.request.call_args.args
    assert args[:2] == ("PUT", "https://api.github.com/repos/acme/widget/pulls/7/merge")
    assert args[3] == {key: value for key, value in inputs.items() if key != "pull_number"}
    credentials.token_for.assert_called_once_with("acme/widget", "github.merge_pull_request")


@pytest.mark.parametrize("field,value", [
    ("sha", None), ("sha", True), ("sha", "a" * 39), ("sha", "a" * 41),
    ("sha", "g" * 40), ("sha", "a" * 40 + "\n"), ("sha", " " + "a" * 40),
    ("pull_number", True), ("pull_number", 0), ("pull_number", -1),
    ("pull_number", "7"), ("pull_number", 7.5),
    ("merge_method", "auto"), ("merge_method", "MERGE"), ("merge_method", None),
    ("commit_title", False), ("commit_message", []), ("unexpected", "field"),
])
def test_invalid_merge_fails_before_credentials(field, value):
    credentials, transport = Mock(), Mock()
    adapter = GitHubAppActionAdapter(credentials, transport=transport)
    with pytest.raises(GitHubExecutorError):
        adapter.execute_action(intent({**INPUT, field: value}))
    credentials.token_for.assert_not_called()
    transport.request.assert_not_called()


@pytest.mark.parametrize("field", ["sha", "pull_number", "merge_method"])
def test_missing_required_merge_fields(field):
    inputs = dict(INPUT)
    del inputs[field]
    with pytest.raises(GitHubExecutorError):
        GitHubAppActionAdapter(Mock()).execute_action(intent(inputs))


@pytest.mark.parametrize("response", [{}, {"merged": False}, {"merged": 1},
                                      {"merged": "true"}, {"merged": None}, []])
def test_merge_requires_literal_true(response):
    transport = Mock()
    transport.request.return_value = response
    result = GitHubAppActionAdapter(Mock(token_for=lambda *args: "secret"),
                                    transport=transport).execute_action(intent())
    assert result.status == "FAILED"
    assert result.payload == {"error_code": "TEMPUS_GITHUB_BINDING_REJECTED"}
    transport.request.assert_called_once()


@pytest.mark.parametrize("status,message", [
    (405, "Pull request is not mergeable"), (409, "Pull request HEAD SHA changed"),
])
def test_merge_deterministic_errors(status, message):
    transport = Mock()
    transport.request.side_effect = GitHubAPIError(status, "secret")
    result = GitHubAppActionAdapter(Mock(token_for=lambda *args: "secret"),
                                    transport=transport).execute_action(intent())
    assert result.status == "FAILED"
    assert result.payload == {"error_code": f"GITHUB_HTTP_{status}", "message": message}
    transport.request.assert_called_once()


@pytest.mark.parametrize("failure", [GitHubAPIError(500, "secret"), TimeoutError("secret")])
def test_merge_ambiguity_never_replayed(failure):
    transport = Mock()
    transport.request.side_effect = failure
    with pytest.raises(AmbiguousTransportError):
        GitHubAppActionAdapter(Mock(token_for=lambda *args: "secret"),
                               transport=transport).execute_action(intent())
    transport.request.assert_called_once()


@pytest.fixture
def signed_merge(tmp_path, app_key):
    env = setup_gate_and_agents(tmp_path)
    action = {**intent(), "schema_version": "tempus.action-intent.v1", "tenant_id": env["tenant_id"],
              "agent_id": env["agent_id"], "idempotency_key": "merge-test",
              "requested_at": time.time_ns() // 1000}
    # This fixture tests cryptographic binding, not production tenant merge governance.
    permit = env["gate"].request_action(json.dumps(action), env["agent_keyfile"], 60)
    auth = MockAppTransport()
    credentials = GitHubAppCredentials("Iv1.merge", str(app_key[0]), 42, "acme/widget", transport=auth)
    transport = Mock()
    transport.request.return_value = {"merged": True, "sha": "c" * 40}
    executor = GitHubAppExecutorAdapter(
        executor_db=env["exec_db"], executor_keyfile=env["exec_keyfile"],
        trusted_gate_id=env["gate_id"], trusted_tenant_id=env["tenant_id"],
        credentials=credentials, transport=transport, gate_db=env["gate_db"],
    )
    return env, permit, executor, auth, transport


def test_signed_merge_and_replay_protection(signed_merge):
    env, permit, executor, auth, transport = signed_merge
    result = executor.execute(permit)
    assert json.loads(result)["status"] == "SUCCEEDED"
    assert json.loads(result)["output"]["merged"] is True
    assert auth.calls[0][3]["permissions"] == {"contents": "write"}
    assert transport.request.call_args.args[3] == {"sha": SHA, "merge_method": "squash"}
    context = transport.request.call_args.kwargs["context"]
    assert context.check_validity() is True
    auth_id = json.loads(permit)["authorization"]["authorization_id"]
    env["gate"].commit_outcome_signed(auth_id, result)
    assert context.check_validity() is False
    with pytest.raises(Exception, match="(?i)already consumed|action ID|outcome"):
        executor.execute(permit)
    transport.request.assert_called_once()


@pytest.mark.parametrize("field,value", [("resource", "other/repo"), ("pull_number", 8),
                                         ("sha", "d" * 40), ("merge_method", "merge")])
def test_signed_merge_tampering_rejected(signed_merge, field, value):
    _, permit, executor, auth, transport = signed_merge
    data = json.loads(permit)
    if field == "resource":
        data["intent"][field] = value
    else:
        data["intent"]["input"][field] = value
    with pytest.raises(Exception, match="(?i)hash|signature|intent"):
        executor.execute(json.dumps(data))
    assert not auth.calls
    transport.request.assert_not_called()


@pytest.mark.parametrize("response", [{"merged": False}, GitHubAPIError(405, "secret"),
                                      GitHubAPIError(409, "secret")])
def test_signed_merge_failure_receipt(signed_merge, response):
    _, permit, executor, _, transport = signed_merge
    if isinstance(response, Exception):
        transport.request.side_effect = response
    else:
        transport.request.return_value = response
    receipt = executor.execute(permit)
    assert json.loads(receipt)["status"] == "FAILED"
    assert "secret" not in receipt
    transport.request.assert_called_once()
