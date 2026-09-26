"""github.push_branch against real git repositories (a bare repo stands in for GitHub)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import Mock

import pytest
from tempus_ddb.executor_runtime import AmbiguousTransportError

from tempus_github_app.credentials import GitHubAppCredentials
from tempus_github_app.executor import GitHubAppActionAdapter, GitHubAppExecutorAdapter
from tempus_github_app.git_push import (
    BundlePublisher,
    GitRunner,
    github_remote_url,
    validate_branch_prefix,
)
from tempus_github_app.transport import GitHubExecutorError, PermitContext
from tests.conftest import MockAppTransport, setup_gate_and_agents

TOKEN = "installation-test-credential"
GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "Agent",
    "GIT_AUTHOR_EMAIL": "agent@example.test",
    "GIT_COMMITTER_NAME": "Agent",
    "GIT_COMMITTER_EMAIL": "agent@example.test",
}


def git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", *args],
        cwd=cwd, env=GIT_ENV, capture_output=True, check=True,
    )
    return completed.stdout.decode().strip()


class Repos:
    """A bare 'GitHub' remote with main at `base`, and an agent clone on agent/fix-123."""

    def __init__(self, root: Path):
        self.root = root
        self.remote = root / "remote.git"
        self.work = root / "work"
        root.mkdir(parents=True, exist_ok=True)
        git(root, "init", "--quiet", "--bare", str(self.remote))
        git(root, "init", "--quiet", str(self.work))
        self.write("README.md", "hello\n")
        self.write(".github/workflows/ci.yml", "on: push\n")
        self.commit("base")
        git(self.work, "push", "--quiet", self.remote.as_uri(), "HEAD:refs/heads/main")
        self.base = self.head()
        git(self.work, "switch", "--quiet", "-c", "agent/fix-123")

    def write(self, relative: str, content: str) -> None:
        path = self.work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        git(self.work, "add", "-A")
        git(self.work, "commit", "--quiet", "--allow-empty", "-m", message)
        return self.head()

    def head(self) -> str:
        return git(self.work, "rev-parse", "HEAD")

    def bundle(self, base: str, name: str = "agent.bundle") -> tuple[Path, str]:
        path = self.root / name
        branch = git(self.work, "rev-parse", "--abbrev-ref", "HEAD")
        git(self.work, "bundle", "create", "--quiet", str(path), f"{base}..{branch}")
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def remote_ref(self, branch: str) -> str | None:
        completed = subprocess.run(
            ["git", "--git-dir", str(self.remote), "rev-parse", "--verify", "--quiet",
             f"refs/heads/{branch}"],
            env=GIT_ENV, capture_output=True, check=False,  # a missing ref is an answer
        )
        return completed.stdout.decode().strip() or None


@pytest.fixture
def repos(tmp_path: Path) -> Repos:
    return Repos(tmp_path)


def make_adapter(repos: Repos, runner: GitRunner | None = None, **kwargs):
    credentials = Mock()
    credentials.token_for.return_value = TOKEN
    publisher = BundlePublisher(
        runner or GitRunner(allowed_protocols=("file",)), work_dir=repos.root
    )
    adapter = GitHubAppActionAdapter(
        credentials, publisher=publisher, remote_url_for=lambda _: repos.remote.as_uri(),
        **kwargs,
    )
    return adapter, credentials


def push_intent(inputs: dict) -> dict:
    return {"action_type": "github.push_branch", "resource": "acme/widget", "input": inputs}


def push_input(repos: Repos, digest: str, paths: list[str], **overrides) -> dict:
    return {
        "branch": "agent/fix-123", "base_sha": repos.base, "tip_sha": repos.head(),
        "new_branch": True, "bundle_sha256": digest, "paths": sorted(paths), **overrides,
    }


def test_creates_branch_at_exact_tip(repos):
    repos.write("src/app.py", "print('fix')\n")
    tip = repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    adapter, credentials = make_adapter(repos)

    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["src/app.py"])), artifacts={"bundle": bundle}
    )

    assert result.status == "SUCCEEDED", result.payload
    assert result.payload == {
        "action_type": "github.push_branch", "resource": "acme/widget",
        "branch": "agent/fix-123", "sha": tip, "base_sha": repos.base,
        "created": True, "up_to_date": False, "paths_count": 1,
    }
    assert repos.remote_ref("agent/fix-123") == tip
    assert repos.remote_ref("main") == repos.base
    credentials.token_for.assert_called_once_with("acme/widget", "github.push_branch")


def test_fast_forwards_existing_branch_only_from_signed_base(repos):
    repos.write("a.txt", "1\n")
    first = repos.commit("first")
    bundle, digest = repos.bundle(repos.base, "first.bundle")
    adapter, _ = make_adapter(repos)
    assert adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt"])), artifacts={"bundle": bundle}
    ).status == "SUCCEEDED"

    repos.write("b.txt", "2\n")
    second = repos.commit("second")
    bundle, digest = repos.bundle(first, "second.bundle")
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["b.txt"], base_sha=first, new_branch=False)),
        artifacts={"bundle": bundle},
    )
    assert result.status == "SUCCEEDED", result.payload
    assert result.payload["created"] is False
    assert repos.remote_ref("agent/fix-123") == second


def test_new_branch_claim_rejected_when_branch_already_exists_elsewhere(repos):
    git(repos.work, "push", "--quiet", repos.remote.as_uri(), f"{repos.base}:refs/heads/agent/fix-123")
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    # The remote branch sits at base, but the agent claims it is new: the lease must refuse.
    bundle, digest = repos.bundle(repos.base)
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt"])), artifacts={"bundle": bundle}
    )
    assert result.status == "FAILED"
    assert result.payload["error_code"] == "GITHUB_PUSH_REJECTED"
    assert repos.remote_ref("agent/fix-123") == repos.base


def test_stale_base_is_rejected_by_lease(repos):
    repos.write("a.txt", "1\n")
    first = repos.commit("first")
    git(repos.work, "push", "--quiet", repos.remote.as_uri(), f"{first}:refs/heads/agent/fix-123")
    repos.write("b.txt", "2\n")
    repos.commit("second")
    # Signed base (main) no longer matches the remote branch (first).
    bundle, digest = repos.bundle(repos.base)
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt", "b.txt"], new_branch=False)),
        artifacts={"bundle": bundle},
    )
    assert result.status == "FAILED"
    assert result.payload["error_code"] == "GITHUB_PUSH_REJECTED"
    assert "stale info" in result.payload["reason"]
    assert repos.remote_ref("agent/fix-123") == first


def test_bundle_digest_mismatch_fails_before_credentials(repos):
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    bundle, _ = repos.bundle(repos.base)
    adapter, credentials = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, "0" * 64, ["a.txt"])), artifacts={"bundle": bundle}
    )
    assert result.payload == {"error_code": "TEMPUS_GITHUB_BUNDLE_MISMATCH"}
    credentials.token_for.assert_not_called()
    assert repos.remote_ref("agent/fix-123") is None


def test_tip_not_in_bundle_is_rejected(repos):
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    repos.write("b.txt", "unbundled\n")
    repos.commit("not in bundle")
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt", "b.txt"])), artifacts={"bundle": bundle}
    )
    assert result.payload == {"error_code": "TEMPUS_GITHUB_BUNDLE_TIP_MISMATCH"}
    assert repos.remote_ref("agent/fix-123") is None


def test_undeclared_path_is_rejected(repos):
    repos.write("src/app.py", "x\n")
    repos.write(".github/workflows/ci.yml", "on: [push, pull_request]\n")
    repos.commit("sneaky workflow change")
    bundle, digest = repos.bundle(repos.base)
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["src/app.py"])), artifacts={"bundle": bundle}
    )
    assert result.payload == {"error_code": "TEMPUS_GITHUB_PATHS_MISMATCH"}
    assert repos.remote_ref("agent/fix-123") is None


def test_paths_cover_renames_deletions_reverted_changes_and_merges(repos):
    (repos.work / "docs").mkdir()
    git(repos.work, "mv", "README.md", "docs/README.md")
    repos.commit("rename")
    repos.write(".github/workflows/ci.yml", "on: workflow_dispatch\n")
    repos.commit("touch workflow")
    repos.write(".github/workflows/ci.yml", "on: push\n")
    repos.commit("revert workflow")  # net diff is empty for the workflow, history is not
    git(repos.work, "switch", "--quiet", "-c", "side", repos.base)
    repos.write("side.txt", "side\n")
    repos.commit("side work")
    git(repos.work, "switch", "--quiet", "agent/fix-123")
    git(repos.work, "merge", "--quiet", "--no-ff", "--no-edit", "side")
    bundle, digest = repos.bundle(repos.base)
    expected = [".github/workflows/ci.yml", "README.md", "docs/README.md", "side.txt"]
    adapter, _ = make_adapter(repos)

    missing_revert = [path for path in expected if not path.startswith(".github")]
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, missing_revert)), artifacts={"bundle": bundle}
    )
    assert result.payload == {"error_code": "TEMPUS_GITHUB_PATHS_MISMATCH"}

    result = adapter.execute_action(
        push_intent(push_input(repos, digest, expected)), artifacts={"bundle": bundle}
    )
    assert result.status == "SUCCEEDED", result.payload
    assert result.payload["paths_count"] == 4


def test_tip_that_does_not_descend_from_base_is_rejected(repos):
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    unrelated = git(repos.work, "commit-tree", "-m", "orphan", f"{repos.base}^{{tree}}")
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt"], base_sha=unrelated)),
        artifacts={"bundle": bundle},
    )
    # The orphan commit is not on the remote, so the base cannot even be fetched.
    assert result.status == "FAILED"
    assert result.payload["error_code"] in {"GITHUB_BASE_UNAVAILABLE", "TEMPUS_GITHUB_NOT_FAST_FORWARD"}
    assert repos.remote_ref("agent/fix-123") is None


@pytest.mark.parametrize("branch", [
    "main", "feature/x", "agent/", "agent", "agent/../main", "agent/x.lock", "agent/.hidden",
    "agent//x", "agent/x/", "agent/x.", "agent/x y", "agent/x~1", "agent/x:y", "refs/heads/agent/x",
])
def test_branch_outside_namespace_fails_before_credentials(repos, branch):
    adapter, credentials = make_adapter(repos)
    with pytest.raises(GitHubExecutorError):
        adapter.execute_action(
            push_intent(push_input(repos, "0" * 64, [], branch=branch)),
            artifacts={"bundle": repos.root / "missing.bundle"},
        )
    credentials.token_for.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("base_sha", "A" * 40), ("base_sha", "a" * 39), ("tip_sha", None), ("tip_sha", "g" * 40),
    ("new_branch", "true"), ("new_branch", 1), ("bundle_sha256", "a" * 63),
    ("bundle_sha256", "A" * 64), ("paths", ["b", "a"]), ("paths", ["a", "a"]),
    ("paths", ["a", 1]), ("paths", [""]), ("paths", "a"), ("paths", ["x"] * 1001),
    ("unexpected", "field"),
])
def test_invalid_push_input_fails_before_credentials(repos, field, value):
    adapter, credentials = make_adapter(repos)
    inputs = push_input(repos, "a" * 64, [], tip_sha="b" * 40)
    inputs[field] = value
    with pytest.raises(GitHubExecutorError):
        adapter.execute_action(push_intent(inputs), artifacts={"bundle": repos.root / "x"})
    credentials.token_for.assert_not_called()


def test_tip_equal_to_base_rejected(repos):
    adapter, _ = make_adapter(repos)
    with pytest.raises(GitHubExecutorError):
        adapter.execute_action(push_intent(push_input(repos, "a" * 64, [], tip_sha=repos.base)),
                               artifacts={"bundle": repos.root / "x"})


def test_missing_bundle_artifact_rejected(repos):
    adapter, credentials = make_adapter(repos)
    with pytest.raises(GitHubExecutorError, match="bundle"):
        adapter.execute_action(push_intent(push_input(repos, "a" * 64, [], tip_sha="b" * 40)))
    credentials.token_for.assert_not_called()


@pytest.mark.parametrize("context", [
    PermitContext(deadline=time.time() - 1),
    PermitContext(deadline=time.time() + 60, check_validity=lambda: False),
    PermitContext(deadline=time.time() + 60, check_validity=Mock(side_effect=OSError)),
])
def test_expired_or_revoked_permit_never_pushes(repos, context):
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    adapter, _ = make_adapter(repos)
    result = adapter.execute_action(
        push_intent(push_input(repos, digest, ["a.txt"])),
        context=context, artifacts={"bundle": bundle},
    )
    assert result.payload == {"error_code": "TEMPUS_GITHUB_PERMIT_INVALID"}
    assert repos.remote_ref("agent/fix-123") is None


class RecordingRunner(GitRunner):
    def __init__(self, push_outcome=None):
        super().__init__(allowed_protocols=("file",))
        self.calls: list[tuple[list[str], dict]] = []
        self.push_outcome = push_outcome

    def run(self, args, *, cwd, config=None, timeout=120.0):
        self.calls.append((list(args), dict(config or {})))
        if args[0] == "push" and self.push_outcome is not None:
            if isinstance(self.push_outcome, BaseException):
                raise self.push_outcome
            return self.push_outcome
        return super().run(args, cwd=cwd, config=config, timeout=timeout)


def _ready_push(repos):
    repos.write("a.txt", "1\n")
    repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    return push_intent(push_input(repos, digest, ["a.txt"])), {"bundle": bundle}


def test_token_only_travels_in_scoped_auth_header(repos):
    runner = RecordingRunner()
    adapter, _ = make_adapter(repos, runner=runner)
    intent, artifacts = _ready_push(repos)
    assert adapter.execute_action(intent, artifacts=artifacts).status == "SUCCEEDED"

    remote = repos.remote.as_uri()
    expected = "AUTHORIZATION: basic " + base64.b64encode(
        f"x-access-token:{TOKEN}".encode()).decode()
    for args, config in runner.calls:
        assert TOKEN not in " ".join(args)
        if args[0] in {"fetch", "push"}:
            assert config == {f"http.{remote}.extraheader": expected}
        else:
            assert config == {}
    assert [args[0] for args, _ in runner.calls] == [
        "init", "fetch", "bundle", "bundle", "cat-file", "merge-base", "diff", "log", "push",
    ]


def test_push_timeout_is_unknown_not_retried(repos):
    runner = RecordingRunner(push_outcome=subprocess.TimeoutExpired(["git", "push"], 1))
    adapter, _ = make_adapter(repos, runner=runner)
    intent, artifacts = _ready_push(repos)
    with pytest.raises(AmbiguousTransportError, match="GITHUB_PUSH_AMBIGUOUS"):
        adapter.execute_action(intent, artifacts=artifacts)
    assert sum(args[0] == "push" for args, _ in runner.calls) == 1


def test_push_failure_without_status_line_is_unknown(repos):
    outcome = subprocess.CompletedProcess(["git"], 128, b"", b"fatal: the remote end hung up")
    adapter, _ = make_adapter(repos, runner=RecordingRunner(push_outcome=outcome))
    intent, artifacts = _ready_push(repos)
    with pytest.raises(AmbiguousTransportError):
        adapter.execute_action(intent, artifacts=artifacts)


@pytest.mark.parametrize("stderr", [
    b"fatal: unable to access 'x': Could not resolve host: github.com",
    b"fatal: unable to access 'x': Failed to connect to github.com port 443",
    b"remote: Permission denied\nfatal: unable to access 'x': The requested URL returned error: 403",
])
def test_push_failure_before_upload_is_failed(repos, stderr):
    outcome = subprocess.CompletedProcess(["git"], 128, b"", stderr)
    adapter, _ = make_adapter(repos, runner=RecordingRunner(push_outcome=outcome))
    intent, artifacts = _ready_push(repos)
    result = adapter.execute_action(intent, artifacts=artifacts)
    assert result.payload == {"error_code": "GITHUB_PUSH_NOT_SENT"}


def test_missing_git_binary_is_failed(repos):
    publisher = BundlePublisher(GitRunner("git-does-not-exist", allowed_protocols=("file",)),
                                work_dir=repos.root)
    credentials = Mock(token_for=Mock(return_value=TOKEN))
    adapter = GitHubAppActionAdapter(credentials, publisher=publisher,
                                     remote_url_for=lambda _: repos.remote.as_uri())
    intent, artifacts = _ready_push(repos)
    result = adapter.execute_action(intent, artifacts=artifacts)
    assert result.payload == {"error_code": "TEMPUS_GITHUB_GIT_UNAVAILABLE"}


def test_https_only_by_default(repos):
    """The production runner refuses file:// remotes (and anything but HTTPS)."""
    credentials = Mock(token_for=Mock(return_value=TOKEN))
    adapter = GitHubAppActionAdapter(
        credentials, publisher=BundlePublisher(work_dir=repos.root),
        remote_url_for=lambda _: repos.remote.as_uri(),
    )
    intent, artifacts = _ready_push(repos)
    result = adapter.execute_action(intent, artifacts=artifacts)
    assert result.payload == {"error_code": "GITHUB_BASE_UNAVAILABLE"}
    assert repos.remote_ref("agent/fix-123") is None


@pytest.mark.parametrize("api_url,expected", [
    ("https://api.github.com", "https://github.com/acme/widget.git"),
    ("https://ghe.example.com/api/v3", "https://ghe.example.com/acme/widget.git"),
    ("https://ghe.example.com/prefix/api/v3/", "https://ghe.example.com/prefix/acme/widget.git"),
])
def test_remote_url_from_api_url(api_url, expected):
    assert github_remote_url(api_url, "acme/widget") == expected


@pytest.mark.parametrize("prefix", ["", "main", "agent", "/", "agent//", ".x/", "a b/"])
def test_branch_prefix_must_be_a_namespace(prefix):
    with pytest.raises(GitHubExecutorError):
        validate_branch_prefix(prefix)
    with pytest.raises(GitHubExecutorError):
        GitHubAppActionAdapter(Mock(), push_branch_prefix=prefix)


def test_custom_prefix_is_enforced(repos):
    adapter, credentials = make_adapter(repos, push_branch_prefix="bots/")
    with pytest.raises(GitHubExecutorError):
        adapter.execute_action(push_intent(push_input(repos, "a" * 64, [], tip_sha="b" * 40)),
                               artifacts={"bundle": repos.root / "x"})
    credentials.token_for.assert_not_called()


# --- Signed permit through the tempus-ddb runtime ------------------------------------------


@pytest.fixture
def signed_push(tmp_path, app_key):
    repos = Repos(tmp_path / "git")
    repos.write("src/app.py", "print('fix')\n")
    repos.commit("fix")
    bundle, digest = repos.bundle(repos.base)
    env = setup_gate_and_agents(tmp_path)
    action = {
        **push_intent(push_input(repos, digest, ["src/app.py"])),
        "schema_version": "tempus.action-intent.v1", "tenant_id": env["tenant_id"],
        "agent_id": env["agent_id"], "idempotency_key": "push-test",
        "requested_at": time.time_ns() // 1000,
    }
    permit = env["gate"].request_action(json.dumps(action), env["agent_keyfile"], 60)
    auth = MockAppTransport()
    credentials = GitHubAppCredentials("Iv1.push", str(app_key[0]), 42, "acme/widget",
                                       transport=auth)
    executor = GitHubAppExecutorAdapter(
        executor_db=env["exec_db"], executor_keyfile=env["exec_keyfile"],
        trusted_gate_id=env["gate_id"], trusted_tenant_id=env["tenant_id"],
        credentials=credentials, gate_db=env["gate_db"],
        publisher=BundlePublisher(GitRunner(allowed_protocols=("file",)), work_dir=tmp_path),
        remote_url_for=lambda _: repos.remote.as_uri(),
    )
    return env, repos, permit, bundle, executor, auth


def test_signed_push_receipt_and_replay_protection(signed_push):
    env, repos, permit, bundle, executor, auth = signed_push
    receipt = json.loads(executor.execute(permit, bundle_path=bundle))
    assert receipt["status"] == "SUCCEEDED"
    assert receipt["output"]["sha"] == repos.head()
    assert auth.calls[0][3]["permissions"] == {"contents": "write"}
    assert repos.remote_ref("agent/fix-123") == repos.head()

    auth_id = json.loads(permit)["authorization"]["authorization_id"]
    env["gate"].commit_outcome_signed(auth_id, json.dumps(receipt))
    with pytest.raises(Exception, match="(?i)already consumed|action ID|outcome"):
        executor.execute(permit, bundle_path=bundle)


def test_signed_push_without_bundle_fails_closed(signed_push):
    _, repos, permit, _, executor, auth = signed_push
    receipt = json.loads(executor.execute(permit))
    assert receipt["status"] == "FAILED"
    assert not auth.calls
    assert repos.remote_ref("agent/fix-123") is None


@pytest.mark.parametrize("field,value", [
    ("tip_sha", "c" * 40), ("branch", "agent/other"), ("bundle_sha256", "d" * 64),
    ("paths", []),
])
def test_signed_push_tampering_rejected(signed_push, field, value):
    _, repos, permit, bundle, executor, auth = signed_push
    data = json.loads(permit)
    data["intent"]["input"][field] = value
    with pytest.raises(Exception, match="(?i)hash|signature|intent"):
        executor.execute(json.dumps(data), bundle_path=bundle)
    assert not auth.calls
    assert repos.remote_ref("agent/fix-123") is None
