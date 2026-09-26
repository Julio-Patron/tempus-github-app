from __future__ import annotations

import time

import jwt
import pytest

from tempus_github_app.credentials import GitHubAppCredentials
from tempus_github_app.transport import GitHubExecutorError, RejectRedirects
from tests.conftest import MockAppTransport


def make_provider(app_key, transport, now):
    return GitHubAppCredentials(
        "Iv1.test",
        str(app_key[0]),
        42,
        "acme/widget",
        transport=transport,
        clock=lambda: now[0],
    )


def test_signed_jwt_scoping_cache_and_refresh(app_key):
    now = [time.time()]
    transport = MockAppTransport(now)
    credentials = make_provider(app_key, transport, now)
    assert (
        credentials.token_for("acme/widget", "github.create_issue") == transport.token
    )
    method, url, headers, payload = transport.calls[0]
    claims = jwt.decode(
        headers["Authorization"][7:], app_key[1].public_key(), algorithms=["RS256"]
    )
    assert claims["iss"] == "Iv1.test"
    assert claims["iat"] == int(now[0]) - 60
    assert claims["exp"] == int(now[0]) + 540
    assert method == "POST"
    assert url == "https://api.github.com/app/installations/42/access_tokens"
    assert payload == {"repositories": ["widget"], "permissions": {"issues": "write"}}

    # Cached hit
    credentials.token_for("ACME/Widget", "github.create_issue")
    assert len(transport.calls) == 1

    # Different permission mints fresh token
    credentials.token_for("acme/widget", "github.create_pull_request")
    assert transport.calls[-1][3]["permissions"] == {"pull_requests": "write"}

    # Expiry refresh
    now[0] += 3541
    credentials.token_for("acme/widget", "github.create_issue")
    assert len(transport.calls) == 3


@pytest.mark.parametrize(
    ("resource", "action"),
    [
        ("other/widget", "github.create_issue"),
        ("acme/other", "github.create_issue"),
        ("acme/widget", "github.delete_repository"),
    ],
    ids=["different-owner", "different-repository", "unsupported-action"],
)
def test_binding_rejected_before_authentication(app_key, resource, action):
    now = [time.time()]
    transport = MockAppTransport(now)
    with pytest.raises(GitHubExecutorError, match="outside"):
        make_provider(app_key, transport, now).token_for(resource, action)
    assert not transport.calls


@pytest.mark.parametrize("token", [None, "", 123])
def test_malformed_token_fails_closed(app_key, token):
    now = [time.time()]
    transport = MockAppTransport(now)
    transport.token = token
    with pytest.raises(GitHubExecutorError, match="authentication failed"):
        make_provider(app_key, transport, now).token_for(
            "acme/widget", "github.create_issue"
        )


def test_redirects_cannot_forward_credentials():
    with pytest.raises(GitHubExecutorError, match="redirects"):
        RejectRedirects().redirect_request(
            None, None, 307, "", {}, "https://other.test"
        )


@pytest.mark.parametrize("action,permission", [
    ("github.add_comment", "issues"),
    ("github.add_labels", "issues"),
    ("github.request_review", "pull_requests"),
    ("github.merge_pull_request", "contents"),
    ("github.push_branch", "contents"),
])
def test_new_action_token_scope(app_key, action, permission):
    now = [time.time()]
    transport = MockAppTransport(now)
    credentials = make_provider(app_key, transport, now)
    credentials.token_for("acme/widget", action)
    assert transport.calls[0][3] == {
        "repositories": ["widget"], "permissions": {permission: "write"},
    }


def test_credentials_from_pem_string_and_base64(app_key, monkeypatch):
    import base64
    from pathlib import Path

    pem_bytes = Path(app_key[0]).read_bytes()
    b64_str = base64.b64encode(pem_bytes).decode("ascii")
    now = [time.time()]
    transport = MockAppTransport(now)

    # 1. From PEM string
    creds_pem = GitHubAppCredentials(
        client_id="Iv1.test",
        installation_id=42,
        repository="acme/widget",
        private_key_pem=pem_bytes.decode("utf-8"),
        transport=transport,
        clock=lambda: now[0],
    )
    assert creds_pem.token_for("acme/widget", "github.create_issue") == transport.token

    # 2. From base64 string in private_key_pem
    creds_b64 = GitHubAppCredentials(
        client_id="Iv1.test",
        installation_id=42,
        repository="acme/widget",
        private_key_pem=b64_str,
        transport=transport,
        clock=lambda: now[0],
    )
    assert creds_b64.token_for("acme/widget", "github.create_issue") == transport.token

    # 3. From environment variable GITHUB_APP_PRIVATE_KEY_BASE64
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_BASE64", b64_str)
    creds_env = GitHubAppCredentials(
        client_id="Iv1.test",
        installation_id=42,
        repository="acme/widget",
        transport=transport,
        clock=lambda: now[0],
    )
    assert creds_env.token_for("acme/widget", "github.create_issue") == transport.token

