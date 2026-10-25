import json
import sqlite3
import time
from contextlib import closing
from unittest.mock import MagicMock

import pytest
from tempus_ddb.executor_runtime import UnknownExecutionError

from tempus_github_app.credentials import GitHubAppCredentials
from tempus_github_app.executor import GitHubAppExecutorAdapter
from tempus_github_app.permit_context import verified_permit_context
from tempus_github_app.transport import GitHubPermitError, UrllibGitHubTransport
from tests.conftest import MockAppTransport, setup_gate_and_agents
from tests.test_transport_resilience import http_error


@pytest.fixture
def execution(tmp_path, app_key, monkeypatch):
    env = setup_gate_and_agents(tmp_path)
    intent = {
        "schema_version": "tempus.action-intent.v1", "tenant_id": env["tenant_id"],
        "agent_id": env["agent_id"], "idempotency_key": "retry-test",
        "action_type": "github.create_issue", "resource": "acme/widget",
        "requested_at": time.time_ns() // 1000, "input": {"title": "Retry test"},
    }
    permit = env["gate"].request_action(json.dumps(intent), env["agent_keyfile"], 60)
    now = [time.time()]
    sleeps = []
    opener = MagicMock()
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b'{"id": 1, "number": 1}'
    opener.open.return_value = response
    monkeypatch.setattr("tempus_github_app.transport.request.build_opener", lambda *args: opener)

    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    transport = UrllibGitHubTransport(clock=lambda: now[0], monotonic=lambda: now[0], sleep=sleep)
    auth = MockAppTransport()
    credentials = GitHubAppCredentials("Iv1.test", str(app_key[0]), 42, "acme/widget", transport=auth)
    executor = GitHubAppExecutorAdapter(
        executor_db=env["exec_db"], executor_keyfile=env["exec_keyfile"],
        trusted_gate_id=env["gate_id"], trusted_tenant_id=env["tenant_id"],
        credentials=credentials, transport=transport, gate_db=env["gate_db"],
    )
    return env, permit, executor, transport, opener, response, sleeps, auth


def authorization_of(permit: str) -> dict:
    return json.loads(permit)["authorization"]


def with_duplicate_authorization(permit: str) -> str:
    """Insert a second authorization key before the signed one.

    A last-key-wins parser would still see the signed object and could proceed.
    """
    needle = '"authorization":'
    index = permit.find(needle)
    assert index != -1
    return f'{permit[:index]}"authorization":{{"expires_at":1}},{permit[index:]}'


def revoke(env, permit, identity=False):
    authorization = json.loads(permit)["authorization"]
    with closing(sqlite3.connect(env["gate_db"])) as connection:
        if identity:
            connection.execute(
                "INSERT INTO identity_lifecycle_events "
                "(event_id, identity_id, public_key, event_type, effective_at, event_json) "
                "VALUES ('retry-event', ?, ?, 'REVOKE', ?, '{}')",
                (env["agent_id"], env["agent_id"], time.time_ns() // 1000),
            )
        else:
            connection.execute(
                "INSERT INTO revoked_authorizations "
                "(authorization_id, revoked_at, reason, identity_event_id) VALUES (?, ?, 'test', 'evt')",
                (authorization["authorization_id"], time.time_ns() // 1000),
            )
        connection.commit()


def test_verified_context_retry_and_atomic_consumption(execution):
    env, permit, executor, _, opener, response, sleeps, auth = execution
    calls = []

    def request(*args, **kwargs):
        with closing(sqlite3.connect(env["exec_db"])) as connection:
            rows = connection.execute("SELECT status FROM consumed_permits").fetchall()
        assert rows == [("STARTED",)]
        calls.append(kwargs["timeout"])
        if len(calls) == 1:
            raise http_error(headers={"Retry-After": "2"})
        return response

    opener.open.side_effect = request
    outcome = executor.execute(permit)
    assert json.loads(outcome)["status"] == "SUCCEEDED"
    assert sleeps == [2]
    assert len(calls) == 2
    assert len(auth.calls) == 1
    assert auth.token not in outcome
    with pytest.raises(Exception, match="already consumed|action ID"):
        executor.execute(permit)
    assert len(calls) == 2


@pytest.mark.parametrize("identity", [False, True])
def test_revocation_during_wait_produces_failed_receipt(execution, identity):
    env, permit, executor, transport, opener, _, _, _ = execution
    opener.open.side_effect = http_error(headers={"Retry-After": "2"})
    sleep = transport._sleep

    def revoke_and_sleep(delay):
        revoke(env, permit, identity)
        sleep(delay)

    transport._sleep = revoke_and_sleep
    outcome = json.loads(executor.execute(permit))
    assert outcome["status"] == "FAILED"
    assert outcome["output"]["error_code"] == "TEMPUS_GITHUB_PERMIT_INVALID"
    assert opener.open.call_count == 1


@pytest.mark.parametrize("failure", [TimeoutError("secret"), http_error(500)])
def test_ambiguous_execution_is_unknown_and_not_replayed(execution, failure):
    _, permit, executor, _, opener, _, sleeps, _ = execution
    opener.open.side_effect = failure
    with pytest.raises(UnknownExecutionError):
        executor.execute(permit)
    authorization_id = json.loads(permit)["authorization"]["authorization_id"]
    state = executor.get_execution_state(authorization_id)
    assert "UNKNOWN" in state
    assert "secret" not in state
    assert not sleeps
    assert opener.open.call_count == 1
    with pytest.raises(Exception, match="already consumed|action ID"):
        executor.execute(permit)
    assert opener.open.call_count == 1


def test_tampered_expiry_never_reaches_context_or_credentials(execution):
    _, permit, executor, _, opener, _, _, auth = execution
    data = json.loads(permit)
    data["authorization"]["expires_at"] += 1_000_000
    with pytest.raises(Exception, match="(?i)signature|hash|authorization"):
        executor.execute(json.dumps(data))
    assert not auth.calls
    opener.open.assert_not_called()


def test_context_uses_signed_microseconds_and_fresh_revocation(execution):
    env, permit, _, _, _, _, _, _ = execution
    authorization = authorization_of(permit)
    context = verified_permit_context(authorization, env["gate_db"])
    assert context.deadline == authorization["expires_at"] / 1_000_000
    assert context.check_validity() is True
    revoke(env, permit)
    assert context.check_validity() is False
    assert verified_permit_context(authorization, None).check_validity is None


def test_missing_db_is_not_created(execution, tmp_path):
    _, permit, _, _, _, _, _, _ = execution
    missing = tmp_path / "missing.db"
    context = verified_permit_context(authorization_of(permit), str(missing))
    assert context.check_validity() is False
    assert not missing.exists()


def test_schema_mismatch_fails_closed(execution, tmp_path):
    _, permit, _, _, _, _, _, _ = execution
    db = tmp_path / "empty.db"
    db.touch()
    assert verified_permit_context(authorization_of(permit), str(db)).check_validity() is False


def test_permission_denied_is_failed(execution):
    _, permit, executor, _, opener, _, sleeps, _ = execution
    opener.open.side_effect = http_error(403, message="Resource not accessible by integration")
    outcome = json.loads(executor.execute(permit))
    assert outcome["status"] == "FAILED"
    assert outcome["output"]["error_code"] == "GITHUB_HTTP_403"
    assert not sleeps
    assert opener.open.call_count == 1


def test_without_gate_db_rate_limit_is_not_retried(execution):
    _, permit, executor, _, opener, _, sleeps, _ = execution
    executor._gate_db = None
    opener.open.side_effect = http_error(headers={"Retry-After": "1"})
    outcome = json.loads(executor.execute(permit))
    assert outcome["status"] == "FAILED"
    assert outcome["output"]["error_code"] == "GITHUB_HTTP_429"
    assert opener.open.call_count == 1
    assert not sleeps


def test_legacy_transport_with_gate_db_is_rejected(execution):
    _, permit, executor, _, opener, _, _, _ = execution

    class LegacyTransport:
        def request(self, method, url, headers, payload):
            pytest.fail("Legacy transport must not receive a write requiring active revocation")

    executor._adapter._transport = LegacyTransport()
    assert json.loads(executor.execute(permit))["status"] == "FAILED"
    opener.open.assert_not_called()


def test_untrusted_custom_ambiguity_reason_is_sanitized(execution):
    from tempus_ddb.executor_runtime import AmbiguousTransportError

    _, permit, executor, _, _, _, _, _ = execution

    class FailingTransport:
        def request(self, method, url, headers, payload, *, context=None):
            raise AmbiguousTransportError("secret installation credential")

    executor._adapter._transport = FailingTransport()
    with pytest.raises(UnknownExecutionError) as caught:
        executor.execute(permit)
    assert "secret" not in str(caught.value)
    auth_id = json.loads(permit)["authorization"]["authorization_id"]
    assert "secret" not in executor.get_execution_state(auth_id)


def test_context_does_not_parse_the_permit(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("permit context parsed JSON")

    monkeypatch.setattr("tempus_github_app.permit_context.loads_strict", boom)
    with pytest.raises(GitHubPermitError, match="verified authorization"):
        verified_permit_context('{"authorization":{"expires_at":1,"authorization":2}}', None)
    authorization = {"expires_at": 2_000_000, "authorization_id": "a", "agent_id": "b"}
    context = verified_permit_context(authorization, None)
    assert context.deadline == 2
    assert context.check_validity is None


def test_execute_uses_verified_authorization_object(execution, monkeypatch):
    env, permit, executor, _, _, _, _, _ = execution
    captured = {}
    original = verified_permit_context

    def spy(authorization, gate_db):
        captured["authorization"] = authorization
        captured["gate_db"] = gate_db
        return original(authorization, gate_db)

    monkeypatch.setattr("tempus_github_app.permit_context.verified_permit_context", spy)
    executor.execute(permit)
    assert captured["authorization"] == authorization_of(permit)
    assert captured["gate_db"] == env["gate_db"]
    assert "intent" not in captured["authorization"]


def test_duplicate_authorization_is_rejected(execution):
    _, permit, executor, _, opener, _, _, auth = execution
    duplicate = with_duplicate_authorization(permit)
    with pytest.raises(json.JSONDecodeError, match="DUPLICATE_JSON_KEY"):
        executor.execute(duplicate)
    assert not auth.calls
    opener.open.assert_not_called()
    # The signed permit was not consumed by the collapsed reading.
    assert json.loads(executor.execute(permit))["status"] == "SUCCEEDED"
