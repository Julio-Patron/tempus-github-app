"""Publish an agent's git bundle to one GitHub branch under an exact-SHA permit.

The agent never holds a write credential. It hands the executor a git bundle
whose sha256, tip commit, base commit and changed paths are all bound into the
signed intent. The executor re-derives each of those facts from the bundle
before the only write, and then creates or fast-forwards exactly one branch.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import parse

from tempus_ddb.executor_runtime import AmbiguousTransportError, ExecutionResult

from .transport import (
    GitHubExecutorError,
    GitHubPermitError,
    PermitContext,
    validate_github_api_url,
)

PUSH_ACTION = "github.push_branch"
DEFAULT_BRANCH_PREFIX = "agent/"
MAX_PATHS = 1000
MAX_BUNDLE_BYTES = 100 * 1024 * 1024

_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_BRANCH_PATTERN = re.compile(r"[A-Za-z0-9._/-]{1,200}")
_PUSH_FIELDS = {"branch", "base_sha", "tip_sha", "new_branch", "bundle_sha256", "paths"}
# Failures reported before git sends a pack: nothing can have been written.
_NOT_SENT_MARKERS = (
    "could not resolve host",
    "failed to connect",
    "couldn't connect",
    "the requested url returned error: 4",
)
# Only what git needs to start; never the operator's git or credential config.
_ENV_PASSTHROUGH = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE")


@dataclass(frozen=True)
class PushRequest:
    """The signed facts a push must match exactly."""

    branch: str
    base_sha: str
    tip_sha: str
    new_branch: bool
    bundle_sha256: str
    paths: tuple[str, ...]


def validate_branch_prefix(prefix: str) -> str:
    """A prefix must name a namespace such as ``agent/``; an empty one would allow ``main``."""
    if (
        not isinstance(prefix, str)
        or not prefix.endswith("/")
        or not _BRANCH_PATTERN.fullmatch(prefix)
        or not _valid_ref_components(prefix[:-1])
    ):
        raise GitHubExecutorError("push branch prefix must be a namespace ending in '/'")
    return prefix


def _valid_ref_components(name: str) -> bool:
    return all(
        component and not component.startswith(".") and not component.endswith(".lock")
        for component in name.split("/")
    )


def parse_push_request(action_input: Mapping[str, Any], branch_prefix: str) -> PushRequest:
    """Validate intent.input for github.push_branch; nothing here touches credentials."""
    unknown = sorted(set(action_input) - _PUSH_FIELDS)
    if unknown:
        raise GitHubExecutorError(f"unsupported input fields: {', '.join(unknown)}")

    branch = action_input.get("branch")
    if (
        not isinstance(branch, str)
        or not _BRANCH_PATTERN.fullmatch(branch)
        or not branch.startswith(branch_prefix)
        or len(branch) == len(branch_prefix)
        or ".." in branch
        or branch.endswith((".", "/"))
        or not _valid_ref_components(branch)
    ):
        raise GitHubExecutorError(f"branch must be a valid branch name under '{branch_prefix}'")

    shas = {}
    for field in ("base_sha", "tip_sha"):
        value = action_input.get(field)
        if not isinstance(value, str) or not _SHA_PATTERN.fullmatch(value):
            raise GitHubExecutorError(f"{field} must be 40 lowercase hexadecimal characters")
        shas[field] = value
    if shas["base_sha"] == shas["tip_sha"]:
        raise GitHubExecutorError("tip_sha must differ from base_sha")

    new_branch = action_input.get("new_branch")
    if type(new_branch) is not bool:
        raise GitHubExecutorError("new_branch must be a boolean")

    bundle_sha256 = action_input.get("bundle_sha256")
    if not isinstance(bundle_sha256, str) or not _SHA256_PATTERN.fullmatch(bundle_sha256):
        raise GitHubExecutorError("bundle_sha256 must be 64 lowercase hexadecimal characters")

    paths = action_input.get("paths")
    if (
        not isinstance(paths, list)
        or len(paths) > MAX_PATHS
        or not all(isinstance(path, str) and path and "\0" not in path for path in paths)
    ):
        raise GitHubExecutorError(f"paths must be an array of at most {MAX_PATHS} file paths")
    if paths != sorted(set(paths)):
        raise GitHubExecutorError("paths must be sorted and unique")

    return PushRequest(
        branch=branch,
        base_sha=shas["base_sha"],
        tip_sha=shas["tip_sha"],
        new_branch=new_branch,
        bundle_sha256=bundle_sha256,
        paths=tuple(paths),
    )


def github_remote_url(api_url: str, resource: str) -> str:
    """Derive the HTTPS git remote for a repository from the REST API endpoint."""
    parsed = parse.urlsplit(validate_github_api_url(api_url))
    if parsed.netloc.lower() == "api.github.com":
        return f"https://github.com/{resource}.git"
    prefix = parsed.path[: -len("/api/v3")] if parsed.path.endswith("/api/v3") else ""
    return f"https://{parsed.netloc}{prefix}/{resource}.git"


class GitUnavailableError(GitHubExecutorError):
    """The git binary could not be started, so nothing was sent."""


class GitRunner:
    """Run git without system/global config, hooks, prompts or credential helpers.

    Operator configuration such as ``url.<base>.insteadOf`` could redirect the
    installation token to another host, so none of it is loaded.
    """

    def __init__(self, git: str = "git", *, allowed_protocols: Sequence[str] = ("https",)):
        self._git = git
        self._allowed_protocols = tuple(allowed_protocols)

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        config: Mapping[str, str] | None = None,
        timeout: float = 120.0,
    ) -> subprocess.CompletedProcess[bytes]:
        settings = {
            "protocol.allow": "never",
            **{f"protocol.{name}.allow": "always" for name in self._allowed_protocols},
            "http.followRedirects": "false",
            "credential.helper": "",
            "core.hooksPath": os.devnull,
            "core.fsmonitor": "false",
            "transfer.fsckObjects": "true",
            **(config or {}),
        }
        env = {name: os.environ[name] for name in _ENV_PASSTHROUGH if name in os.environ}
        env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "GIT_CONFIG_COUNT": str(len(settings)),
        })
        for index, (key, value) in enumerate(settings.items()):
            env[f"GIT_CONFIG_KEY_{index}"] = key
            env[f"GIT_CONFIG_VALUE_{index}"] = value
        try:
            return subprocess.run(
                [self._git, *args],
                cwd=cwd,
                env=env,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except OSError:
            raise GitUnavailableError("git executable could not be started") from None


def _failed(error_code: str, **extra: Any) -> ExecutionResult:
    return ExecutionResult(status="FAILED", payload={"error_code": error_code, **extra})


def _remove_readonly(function: Callable[..., Any], path: str, _info: Any) -> None:
    # Git writes read-only pack files, which Windows refuses to delete as-is.
    os.chmod(path, stat.S_IWRITE)
    function(path)


class BundlePublisher:
    """Verify a bundle against its push request and publish it with one lease-guarded push."""

    def __init__(
        self,
        runner: GitRunner | None = None,
        *,
        work_dir: str | Path | None = None,
        git_timeout: float = 120.0,
        max_bundle_bytes: int = MAX_BUNDLE_BYTES,
        clock: Callable[[], float] = time.time,
    ):
        self._runner = runner or GitRunner()
        self._work_dir = work_dir
        self._git_timeout = git_timeout
        self._max_bundle_bytes = max_bundle_bytes
        self._clock = clock

    def bundle_matches(self, bundle_path: str | Path, expected_sha256: str) -> bool:
        """Check size and sha256 before any credential is minted."""
        path = Path(bundle_path)
        try:
            size = path.stat().st_size
            if not 0 < size <= self._max_bundle_bytes:
                return False
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            return False
        return hmac.compare_digest(digest.hexdigest(), expected_sha256)

    def publish(
        self,
        request: PushRequest,
        bundle_path: str | Path,
        remote_url: str,
        token: str,
        context: PermitContext | None,
        resource: str,
    ) -> ExecutionResult:
        workspace = Path(tempfile.mkdtemp(prefix="tempus-push-", dir=self._work_dir))
        try:
            return self._publish(
                request, Path(bundle_path).resolve(), remote_url, token, context, resource,
                workspace,
            )
        finally:
            if sys.version_info >= (3, 12):
                shutil.rmtree(workspace, onexc=_remove_readonly)
            else:
                shutil.rmtree(workspace, onerror=_remove_readonly)

    def _publish(
        self,
        request: PushRequest,
        bundle: Path,
        remote_url: str,
        token: str,
        context: PermitContext | None,
        resource: str,
        workspace: Path,
    ) -> ExecutionResult:
        repo = workspace / "repo.git"
        if self._git(["init", "--quiet", "--bare", str(repo)], cwd=workspace).returncode != 0:
            return _failed("TEMPUS_GITHUB_WORKSPACE_FAILED")
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
        auth = {f"http.{remote_url}.extraheader": f"AUTHORIZATION: basic {basic}"}

        # Reads only: the bundle is thin, so its base must come from GitHub itself.
        fetched = self._git(
            ["fetch", "--quiet", "--no-tags", "--depth=1", remote_url, request.base_sha],
            cwd=repo, config=auth,
        )
        if fetched.returncode != 0:
            return _failed("GITHUB_BASE_UNAVAILABLE")
        if self._git(["bundle", "verify", "--quiet", str(bundle)], cwd=repo).returncode != 0:
            return _failed("TEMPUS_GITHUB_BUNDLE_INVALID")
        unbundled = self._git(["bundle", "unbundle", str(bundle)], cwd=repo)
        heads = {
            line.split(b" ", 1)[0].decode("ascii", "replace")
            for line in unbundled.stdout.splitlines() if line.strip()
        }
        if (
            unbundled.returncode != 0
            or request.tip_sha not in heads
            or self._git(["cat-file", "-e", f"{request.tip_sha}^{{commit}}"], cwd=repo).returncode
        ):
            return _failed("TEMPUS_GITHUB_BUNDLE_TIP_MISMATCH")
        ancestry = self._git(
            ["merge-base", "--is-ancestor", request.base_sha, request.tip_sha], cwd=repo
        )
        if ancestry.returncode != 0:
            return _failed("TEMPUS_GITHUB_NOT_FAST_FORWARD")
        paths = self._changed_paths(repo, request.base_sha, request.tip_sha)
        if paths is None:
            return _failed("TEMPUS_GITHUB_BUNDLE_INVALID")
        if paths != request.paths:
            return _failed("TEMPUS_GITHUB_PATHS_MISMATCH")

        # The only write. The lease pins the remote branch to the signed state, and the
        # ancestry check above makes that update a fast-forward (or a branch creation).
        timeout = self._remaining_budget(context)
        ref = f"refs/heads/{request.branch}"
        lease = f"{ref}:" + ("" if request.new_branch else request.base_sha)
        try:
            pushed = self._git(
                ["push", "--porcelain", "--no-verify", f"--force-with-lease={lease}",
                 remote_url, f"{request.tip_sha}:{ref}"],
                cwd=repo, config=auth, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise AmbiguousTransportError("GITHUB_PUSH_AMBIGUOUS") from None

        status = self._porcelain_status(pushed.stdout, ref)
        if status is None:
            stderr = pushed.stderr.decode("utf-8", "replace").lower()
            if pushed.returncode != 0 and any(marker in stderr for marker in _NOT_SENT_MARKERS):
                return _failed("GITHUB_PUSH_NOT_SENT")
            raise AmbiguousTransportError("GITHUB_PUSH_AMBIGUOUS")
        flag, summary = status
        if flag == "!":
            return _failed("GITHUB_PUSH_REJECTED", reason=summary[:200])
        if flag not in (" ", "*", "+", "="):
            raise AmbiguousTransportError("GITHUB_PUSH_AMBIGUOUS")
        return ExecutionResult(status="SUCCEEDED", payload={
            "action_type": PUSH_ACTION,
            "resource": resource,
            "branch": request.branch,
            "sha": request.tip_sha,
            "base_sha": request.base_sha,
            "created": flag == "*",
            "up_to_date": flag == "=",
            "paths_count": len(paths),
        })

    def _git(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        config: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return self._runner.run(
                args, cwd=cwd, config=config, timeout=timeout or self._git_timeout
            )
        except subprocess.TimeoutExpired:
            if args and args[0] == "push":
                raise
            # A read-only step that hangs has written nothing; report a plain failure.
            return subprocess.CompletedProcess(list(args), 124, b"", b"")

    def _changed_paths(self, repo: Path, base: str, tip: str) -> tuple[str, ...] | None:
        """Every path touched by the pushed commits, including ones a later commit reverts."""
        net = self._git(["diff", "--name-only", "--no-renames", "-z", base, tip], cwd=repo)
        per_commit = self._git(
            ["log", "-m", "--no-renames", "--name-only", "-z", "--format=", f"{base}..{tip}"],
            cwd=repo,
        )
        if net.returncode != 0 or per_commit.returncode != 0:
            return None
        try:
            output = (net.stdout + b"\0" + per_commit.stdout).decode("utf-8")
        except UnicodeDecodeError:
            return None  # Non-UTF-8 paths cannot be matched against the signed list.
        # -z separates names with NUL; stray newlines only come from commit separators.
        return tuple(sorted({name.strip("\n") for name in output.split("\0")} - {""}))

    def _remaining_budget(self, context: PermitContext | None) -> float:
        if context is None:
            return self._git_timeout
        try:
            valid = context.check_validity is None or context.check_validity() is True
        except Exception:  # noqa: BLE001 - a failing verifier must deny the write
            valid = False
        remaining = context.deadline - self._clock()
        if not valid or remaining < 1.0:
            raise GitHubPermitError("Permit expired, revoked, or unverifiable")
        return min(self._git_timeout, remaining)

    @staticmethod
    def _porcelain_status(stdout: bytes, ref: str) -> tuple[str, str] | None:
        for raw in stdout.decode("utf-8", "replace").splitlines():
            parts = raw.split("\t")
            if len(parts) >= 3 and len(parts[0]) == 1 and parts[1].endswith(f":{ref}"):
                return parts[0], parts[2].strip()
        return None
