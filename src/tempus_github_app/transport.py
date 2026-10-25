"""Transport boundary and error handling for GitHub API requests."""

import json
import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from typing import Any, Protocol
from urllib import error, parse, request

from tempus_ddb.executor_runtime import AmbiguousTransportError

from .errors import TRANSPORT_AMBIGUOUS, server_response
from .strict_json import loads as loads_strict

RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def validate_github_api_url(api_url: str) -> str:
    """Accept only an explicit HTTPS GitHub or GitHub Enterprise API endpoint."""
    candidate = api_url.strip().rstrip("/")
    parsed = parse.urlsplit(candidate)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubExecutorError("GitHub API URL must be an absolute HTTPS endpoint")
    return candidate


class GitHubExecutorError(RuntimeError):
    """Base error for configuration and permit failures."""


class GitHubAPIError(GitHubExecutorError):
    """A definitive HTTP response returned by GitHub."""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimitError(GitHubAPIError):
    """A rate-limited write was stopped without another external effect."""


class GitHubPermitError(GitHubExecutorError):
    """The permit cannot authorize a new network attempt."""


@dataclass(frozen=True)
class PermitContext:
    """Trusted execution metadata; never populate this from intent.input.

    deadline is UNIX seconds. check_validity must actively check revocation as
    well as expiry. None permits a first attempt, but never a retry.
    """

    deadline: float
    check_validity: Callable[[], bool] | None = None
    max_retries: int = 3

    def __post_init__(self):
        if (
            type(self.deadline) not in (int, float)
            or not math.isfinite(self.deadline)
            or self.deadline <= 0
            or type(self.max_retries) is not int
            or self.max_retries < 0
            or (self.check_validity is not None and not callable(self.check_validity))
        ):
            raise GitHubPermitError("Invalid permit context")


class GitHubTransport(Protocol):
    """Transport boundary used by the real client and deterministic tests."""

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        context: PermitContext | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Execute one GitHub API request."""


class RejectRedirects(request.HTTPRedirectHandler):
    """Prevent credential forwarding to third-party endpoints."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GitHubExecutorError("GitHub API redirects are not allowed")


class UrllibGitHubTransport:
    """Minimal GitHub REST transport rejecting redirects and enforcing HTTPS."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        context: PermitContext | None = None,
    ) -> dict[str, Any] | list[Any]:
        validate_github_api_url(url)
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        github_request = request.Request(
            url,
            data=encoded,
            headers=headers,
            method=method,
        )
        opener = request.build_opener(RejectRedirects())
        retries = 0
        end = (self._monotonic() + context.deadline - self._clock()) if context else None

        def remaining() -> float:
            if context is None:
                return 30.0
            return min(context.deadline - self._clock(), end - self._monotonic())

        def check_permit() -> None:
            if context is None:
                return
            try:
                valid = context.check_validity is None or context.check_validity() is True
            except Exception:  # noqa: BLE001 - a failing verifier must deny the write
                valid = False
            # Do not round a sub-second remaining budget up to a one-second socket timeout.
            if not valid or remaining() < 1.0:
                raise GitHubPermitError("Permit expired, revoked, or unverifiable")

        while True:
            check_permit()
            try:
                with opener.open(github_request, timeout=min(30.0, remaining())) as response:
                    body = response.read().decode("utf-8")
                    parsed = loads_strict(body) if body else {}
                    if not isinstance(parsed, (dict, list)):
                        raise AmbiguousTransportError(TRANSPORT_AMBIGUOUS)
                    return parsed
            except error.HTTPError as exc:
                # Drain the body so the socket finishes, but do not classify the
                # failure from its text. A 403 that merely says "rate limit" must
                # not cause another write.
                try:
                    exc.read()
                except (OSError, HTTPException):
                    raise AmbiguousTransportError(TRANSPORT_AMBIGUOUS) from None
                finally:
                    exc.close()
                if exc.code >= 500:
                    raise AmbiguousTransportError(server_response(exc.code)) from None
                headers_lower = {key.lower(): value for key, value in (exc.headers or {}).items()}
                limited = exc.code in (403, 429) and (
                    "retry-after" in headers_lower
                    or headers_lower.get("x-ratelimit-remaining") == "0"
                )
                if not limited:
                    raise GitHubAPIError(exc.code, f"GitHub rejected request (HTTP {exc.code})") from None
                if context is None or context.check_validity is None or retries >= context.max_retries:
                    raise GitHubRateLimitError(exc.code, "GitHub rate limit; retries unavailable") from None
                delay = self._retry_delay(headers_lower, retries)
                if delay >= remaining():
                    raise GitHubRateLimitError(exc.code, "GitHub rate limit exceeds permit budget") from None
                check_permit()
                if delay >= remaining():
                    raise GitHubRateLimitError(exc.code, "GitHub rate limit exceeds permit budget") from None
                # A monotonic target also protects against early wakeups and wall-clock changes.
                wake_at = self._monotonic() + delay
                while self._monotonic() < wake_at:
                    self._sleep(wake_at - self._monotonic())
                retries += 1
                # The next loop checks validity again immediately before sending bytes.
            except (OSError, HTTPException, ValueError) as exc:
                raise AmbiguousTransportError(
                    f"GITHUB_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
                ) from None

    def _retry_delay(self, headers: dict[str, str], _retries: int) -> float:
        delays = []
        try:
            if "retry-after" in headers:
                value = headers["retry-after"]
                try:
                    delay = float(value)
                except ValueError:
                    delay = parsedate_to_datetime(value).timestamp() - self._clock()
                delays.append(max(0.0, delay) if math.isfinite(delay) else math.inf)
            if headers.get("x-ratelimit-remaining") == "0":
                reset = float(headers["x-ratelimit-reset"])
                delays.append(max(0.0, reset - self._clock()) if math.isfinite(reset) else math.inf)
        except (ValueError, TypeError, KeyError, OverflowError):
            return math.inf  # An unreadable server deadline cannot safely be shortened.
        # No header deadline means we must not invent a backoff and write again.
        return max(delays) if delays else math.inf
