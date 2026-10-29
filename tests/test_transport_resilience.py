import io
import json
from email.message import Message
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError

import pytest
from tempus_ddb.executor_runtime import AmbiguousTransportError

from tempus_github_app.transport import (
    GitHubAPIError,
    GitHubPermitError,
    GitHubRateLimitError,
    PermitContext,
    UrllibGitHubTransport,
)


def http_error(code=429, headers=None, message="rate limited"):
    metadata = Message()
    for name, value in (headers or {}).items():
        metadata[name] = value
    return HTTPError("https://api.github.com/test", code, "error", metadata,
                     io.BytesIO(json.dumps({"message": message}).encode()))


@pytest.fixture
def network(monkeypatch):
    now = [1_000.0]
    sleeps = []

    def sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    opener = MagicMock()
    response = MagicMock()
    response.__enter__.return_value.read.return_value = b'{"id": 1}'
    opener.open.return_value = response
    monkeypatch.setattr("tempus_github_app.transport.request.build_opener", lambda *args: opener)
    transport = UrllibGitHubTransport(clock=lambda: now[0], sleep=sleep,
                                      monotonic=lambda: now[0])
    return transport, opener, response, now, sleeps


def send(transport, context=None):
    return transport.request("POST", "https://api.github.com/test", {}, {}, context=context)


@pytest.mark.parametrize("code,message", [
    (429, "rate limited"), (403, "You have exceeded a secondary rate limit"),
    (403, "You have triggered an abuse detection mechanism"),
])
def test_retry_success(network, code, message):
    transport, opener, response, now, sleeps = network
    opener.open.side_effect = [http_error(code, {"Retry-After": "10"}, message), response]
    checks = []
    context = PermitContext(1025, lambda: checks.append(now[0]) or True)
    assert send(transport, context) == {"id": 1}
    assert sleeps == [10]
    assert checks[-1] == 1010
    assert [call.kwargs["timeout"] for call in opener.open.call_args_list] == [25, 15]


@pytest.mark.parametrize("context", [None, PermitContext(2000)])
def test_no_retry_without_validity(network, context):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = http_error(headers={"Retry-After": "1"})
    with pytest.raises(GitHubRateLimitError):
        send(transport, context)
    assert opener.open.call_count == 1
    assert not sleeps


@pytest.mark.parametrize("delay", ["25", "26", "3600", "garbage", "nan", "inf"])
def test_budget_exceeded_without_sleep(network, delay):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = http_error(headers={"Retry-After": delay})
    with pytest.raises(GitHubRateLimitError):
        send(transport, PermitContext(1025, lambda: True))
    assert not sleeps
    assert opener.open.call_count == 1


def test_revoked_during_sleep(network):
    transport, opener, _, now, sleeps = network
    opener.open.side_effect = http_error(headers={"Retry-After": "10"})
    with pytest.raises(GitHubPermitError):
        send(transport, PermitContext(1100, lambda: now[0] < 1010))
    assert sleeps == [10]
    assert opener.open.call_count == 1


def test_validity_query_failure(network):
    transport, opener, _, _, sleeps = network

    def check():
        raise RuntimeError("secret database path")

    with pytest.raises(GitHubPermitError) as caught:
        send(transport, PermitContext(1100, check))
    assert "secret" not in str(caught.value)
    assert not sleeps
    opener.open.assert_not_called()


@pytest.mark.parametrize("code,message", [
    (403, "secondary rate limit"),
    (403, "You have triggered an abuse detection mechanism"),
    (429, "rate limited"),
    (429, "You have exceeded a secondary rate limit"),
])
def test_body_text_without_rate_limit_headers_is_not_retried(network, code, message):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = http_error(code, message=message)
    with pytest.raises(GitHubAPIError) as caught:
        send(transport, PermitContext(1500, lambda: True))
    assert not isinstance(caught.value, GitHubRateLimitError)
    assert caught.value.status_code == code
    assert opener.open.call_count == 1
    assert not sleeps


def test_remaining_zero_header_retries_without_reading_body(network):
    transport, opener, response, _, sleeps = network
    opener.open.side_effect = [
        http_error(429, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1020"},
                   message="not a rate limit"),
        response,
    ]
    assert send(transport, PermitContext(1100, lambda: True)) == {"id": 1}
    assert sleeps == [20]
    assert opener.open.call_count == 2


def test_permission_denied_never_retried(network):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = http_error(403, message="Resource not accessible by integration")
    with pytest.raises(GitHubAPIError) as caught:
        send(transport, PermitContext(1500, lambda: True))
    assert not isinstance(caught.value, GitHubRateLimitError)
    assert caught.value.status_code == 403
    assert opener.open.call_count == 1
    assert not sleeps


@pytest.mark.parametrize("failure", [
    TimeoutError("secret"), URLError("secret"), ConnectionResetError("secret"),
    http_error(500, message="secret"), http_error(503, message="secret"),
])
def test_ambiguity_never_retried(network, failure):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = failure
    with pytest.raises(AmbiguousTransportError) as caught:
        send(transport, PermitContext(1500, lambda: True))
    assert "secret" not in str(caught.value)
    assert opener.open.call_count == 1
    assert not sleeps


def test_max_retries(network):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = [http_error(headers={"Retry-After": "1"}) for _ in range(4)]
    with pytest.raises(GitHubRateLimitError):
        send(transport, PermitContext(1500, lambda: True))
    assert opener.open.call_count == 4
    assert sleeps == [1, 1, 1]


@pytest.mark.parametrize("headers,delay", [
    ({"Retry-After": "Thu, 01 Jan 1970 00:17:00 GMT"}, 20),
    ({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1020"}, 20),
    ({"Retry-After": "10", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1020"}, 20),
])
def test_server_deadlines(network, headers, delay):
    transport, opener, response, _, sleeps = network
    opener.open.side_effect = [http_error(headers=headers), response]
    send(transport, PermitContext(1100, lambda: True))
    assert sleeps == [delay]


@pytest.mark.parametrize("deadline", [999, 1000, 1000.5])
def test_insufficient_initial_budget(network, deadline):
    transport, opener, _, _, _ = network
    with pytest.raises(GitHubPermitError):
        send(transport, PermitContext(deadline, lambda: True))
    opener.open.assert_not_called()


def test_expiry_while_sleeping(network):
    transport, opener, _, now, _ = network
    transport._sleep = lambda delay: now.__setitem__(0, now[0] + delay + 100)
    opener.open.side_effect = http_error(headers={"Retry-After": "10"})
    with pytest.raises(GitHubPermitError):
        send(transport, PermitContext(1050, lambda: True))
    assert opener.open.call_count == 1


def test_backward_wall_clock_does_not_extend_budget(network):
    transport, opener, _, now, _ = network
    wall = [1000.0]
    transport._clock = lambda: wall[0]

    def sleep(delay):
        now[0] += 100
        wall[0] -= 100

    transport._sleep = sleep
    opener.open.side_effect = http_error(headers={"Retry-After": "10"})
    with pytest.raises(GitHubPermitError):
        send(transport, PermitContext(1050, lambda: True))
    assert opener.open.call_count == 1


@pytest.mark.parametrize("value", [float("nan"), float("inf"), True, "1000", -1])
def test_invalid_deadline(value):
    with pytest.raises(GitHubPermitError):
        PermitContext(value)


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_invalid_retry_count(value):
    with pytest.raises(GitHubPermitError):
        PermitContext(2000, max_retries=value)


def test_zero_retries(network):
    transport, opener, _, _, sleeps = network
    opener.open.side_effect = http_error(headers={"Retry-After": "1"})
    with pytest.raises(GitHubRateLimitError):
        send(transport, PermitContext(2000, lambda: True, max_retries=0))
    assert not sleeps
    assert opener.open.call_count == 1


def test_duplicate_key_success_is_ambiguous(network):
    transport, opener, response, _, sleeps = network
    response.__enter__.return_value.read.return_value = b'{"id":1,"id":2}'
    with pytest.raises(AmbiguousTransportError):
        send(transport, PermitContext(2000, lambda: True))
    assert opener.open.call_count == 1
    assert not sleeps


def test_duplicate_key_error_body_is_not_a_rate_limit(network):
    transport, opener, _, _, sleeps = network
    metadata = Message()
    failure = HTTPError(
        "https://api.github.com/test",
        403,
        "error",
        metadata,
        io.BytesIO(b'{"message":"ok","message":"rate limit"}'),
    )
    opener.open.side_effect = failure
    with pytest.raises(GitHubAPIError) as caught:
        send(transport, PermitContext(2000, lambda: True))
    assert not isinstance(caught.value, GitHubRateLimitError)
    assert caught.value.status_code == 403
    assert opener.open.call_count == 1
    assert not sleeps


@pytest.mark.parametrize("body", [b"invalid JSON", b"42", b"null"])
def test_malformed_success_is_ambiguous(network, body):
    transport, opener, response, _, sleeps = network
    response.__enter__.return_value.read.return_value = body
    with pytest.raises(AmbiguousTransportError):
        send(transport, PermitContext(2000, lambda: True))
    assert opener.open.call_count == 1
    assert not sleeps


def test_early_wakeup_respects_entire_delay(network):
    transport, opener, response, now, sleeps = network

    def sleep(delay):
        sleeps.append(delay)
        now[0] += min(delay, 2)

    transport._sleep = sleep
    opener.open.side_effect = [http_error(headers={"Retry-After": "5"}), response]
    send(transport, PermitContext(2000, lambda: True))
    assert now[0] == 1005
    assert sleeps == [5, 3, 1]
