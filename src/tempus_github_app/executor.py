"""Credential-isolated GitHub App executor for Tempus permits."""

from __future__ import annotations

import inspect
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, ClassVar

from tempus_ddb.executor_runtime import (
    ActionAdapter,
    AmbiguousTransportError,
    ExecutionResult,
    ExecutorRuntime,
)

from .credentials import GitHubAppCredentials
from .git_push import (
    DEFAULT_BRANCH_PREFIX,
    PUSH_ACTION,
    BundlePublisher,
    GitUnavailableError,
    github_remote_url,
    parse_push_request,
    validate_branch_prefix,
)
from .permit_context import PermitBoundActionAdapter
from .transport import (
    RESOURCE_PATTERN,
    GitHubAPIError,
    GitHubExecutorError,
    GitHubPermitError,
    GitHubTransport,
    PermitContext,
    UrllibGitHubTransport,
    validate_github_api_url,
)


class GitHubAppActionAdapter(ActionAdapter):
    """ActionAdapter implementation for GitHub REST API writes using GitHub App installation tokens."""

    unsupported_error_code = "TEMPUS_GITHUB_BINDING_REJECTED"

    SUPPORTED_ACTIONS: ClassVar[set[str]] = {
        "github.create_issue",
        "github.create_pull_request",
        "github.add_comment",
        "github.add_labels",
        "github.request_review",
        "github.merge_pull_request",
        PUSH_ACTION,
    }

    def __init__(
        self,
        credentials: GitHubAppCredentials,
        api_url: str = "https://api.github.com",
        transport: GitHubTransport | None = None,
        *,
        push_branch_prefix: str = DEFAULT_BRANCH_PREFIX,
        publisher: BundlePublisher | None = None,
        remote_url_for: Callable[[str], str] | None = None,
    ):
        self._credentials = credentials
        self._api_url = validate_github_api_url(api_url)
        self._transport = transport or UrllibGitHubTransport()
        self._push_branch_prefix = validate_branch_prefix(push_branch_prefix)
        self._publisher = publisher or BundlePublisher()
        self._remote_url_for = remote_url_for or (
            lambda resource: github_remote_url(self._api_url, resource)
        )

    @property
    def supported_actions(self) -> set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(
        self,
        intent: dict[str, Any],
        *,
        context: PermitContext | None = None,
        artifacts: Mapping[str, str | Path] | None = None,
    ) -> ExecutionResult:
        if intent.get("action_type") == PUSH_ACTION:
            return self._push_branch(intent, context, artifacts or {})
        method, url, payload, action_type, resource = self._bind_request(intent)

        try:
            token = self._credentials.token_for(resource, action_type)
        except Exception:  # noqa: BLE001
            # Never leak credential details or stack trace
            return ExecutionResult(
                status="FAILED",
                payload={"error_code": "TEMPUS_GITHUB_CREDENTIAL_REJECTED"},
            )

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "tempus-github-app-executor/0.1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            if context is not None:
                try:
                    valid = context.check_validity is None or context.check_validity() is True
                except Exception:  # noqa: BLE001 - verifier failures deny execution
                    valid = False
                if not valid or time.time() >= context.deadline:
                    raise GitHubPermitError("Permit expired, revoked, or unverifiable")
                parameters = inspect.signature(self._transport.request).parameters
                accepts_context = "context" in parameters or any(
                    parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
                if not accepts_context and context.check_validity is not None:
                    raise GitHubPermitError("Transport does not support permit context")
            else:
                accepts_context = False
            kwargs = {"context": context} if accepts_context else {}
            response = self._transport.request(method, url, headers, payload, **kwargs)
            if action_type == "github.merge_pull_request" and (
                not isinstance(response, dict) or response.get("merged") is not True
            ):
                return ExecutionResult(
                    status="FAILED", payload={"error_code": "GITHUB_MERGE_NOT_CONFIRMED"}
                )
            result = self._sanitize_result(response, action_type, resource)
            return ExecutionResult(status="SUCCEEDED", payload=result)
        except GitHubAPIError as exc:
            if exc.status_code >= 500:
                raise AmbiguousTransportError(
                    f"GITHUB_SERVER_RESPONSE_{exc.status_code}"
                ) from exc
            return ExecutionResult(
                status="FAILED",
                payload={
                    "error_code": f"GITHUB_HTTP_{exc.status_code}",
                    "message": (
                        {405: "Pull request is not mergeable", 409: "Pull request HEAD SHA changed"}
                        .get(exc.status_code, f"GitHub request rejected (HTTP {exc.status_code})")
                        if action_type == "github.merge_pull_request"
                        else f"GitHub request rejected (HTTP {exc.status_code})"
                    ),
                },
            )
        except GitHubPermitError:
            return ExecutionResult(
                status="FAILED", payload={"error_code": "TEMPUS_GITHUB_PERMIT_INVALID"}
            )
        except AmbiguousTransportError:
            # Custom transports must not leak response bodies or credentials in reasons.
            raise AmbiguousTransportError("GITHUB_TRANSPORT_AMBIGUOUS") from None
        except Exception as exc:
            # Ambiguous network outcomes must fail closed as UNKNOWN
            raise AmbiguousTransportError(
                f"GITHUB_TRANSPORT_AMBIGUOUS: {type(exc).__name__}"
            ) from exc

    def _push_branch(
        self,
        intent: dict[str, Any],
        context: PermitContext | None,
        artifacts: Mapping[str, str | Path],
    ) -> ExecutionResult:
        """Publish the permit's git bundle; the bundle travels beside the permit, bound by sha256."""
        resource = self._required_string(intent, "resource")
        if not RESOURCE_PATTERN.fullmatch(resource):
            raise GitHubExecutorError("resource must be an exact 'owner/repository' value")
        action_input = intent.get("input")
        if not isinstance(action_input, dict):
            raise GitHubExecutorError("intent.input must be an object")
        request = parse_push_request(action_input, self._push_branch_prefix)
        bundle = artifacts.get("bundle")
        if not bundle:
            raise GitHubExecutorError("github.push_branch requires the permit's bundle artifact")
        if not self._publisher.bundle_matches(bundle, request.bundle_sha256):
            return ExecutionResult(
                status="FAILED", payload={"error_code": "TEMPUS_GITHUB_BUNDLE_MISMATCH"}
            )

        try:
            token = self._credentials.token_for(resource, PUSH_ACTION)
        except Exception:  # noqa: BLE001
            # Never leak credential details or stack trace
            return ExecutionResult(
                status="FAILED",
                payload={"error_code": "TEMPUS_GITHUB_CREDENTIAL_REJECTED"},
            )

        try:
            return self._publisher.publish(
                request, bundle, self._remote_url_for(resource), token, context, resource
            )
        except GitHubPermitError:
            return ExecutionResult(
                status="FAILED", payload={"error_code": "TEMPUS_GITHUB_PERMIT_INVALID"}
            )
        except GitUnavailableError:
            return ExecutionResult(
                status="FAILED", payload={"error_code": "TEMPUS_GITHUB_GIT_UNAVAILABLE"}
            )
        except AmbiguousTransportError:
            # Git output may echo remote URLs; keep the reason fixed.
            raise AmbiguousTransportError("GITHUB_PUSH_AMBIGUOUS") from None

    def _bind_request(
        self, intent: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any], str, str]:
        action_type = self._required_string(intent, "action_type")
        resource = self._required_string(intent, "resource")
        if not RESOURCE_PATTERN.fullmatch(resource):
            raise GitHubExecutorError("resource must be an exact 'owner/repository' value")

        action_input = intent.get("input")
        if not isinstance(action_input, dict):
            raise GitHubExecutorError("intent.input must be an object")

        method = "POST"
        if action_type == "github.merge_pull_request":
            self._reject_unknown_fields(action_input, {
                "pull_number", "sha", "merge_method", "commit_title", "commit_message",
            })
            number = self._positive_integer(action_input, "pull_number")
            sha = self._required_string(action_input, "sha")
            if re.fullmatch(r"[0-9a-fA-F]{40}", sha) is None:
                raise GitHubExecutorError("sha must be exactly 40 hexadecimal characters")
            merge_method = self._required_string(action_input, "merge_method")
            if merge_method not in {"merge", "squash", "rebase"}:
                raise GitHubExecutorError("merge_method must be merge, squash, or rebase")
            payload = {"sha": sha, "merge_method": merge_method}
            for field in ("commit_title", "commit_message"):
                if field in action_input:
                    if not isinstance(action_input[field], str):
                        raise GitHubExecutorError(f"{field} must be a string")
                    payload[field] = action_input[field]
            endpoint = f"/repos/{resource}/pulls/{number}/merge"
            method = "PUT"
        elif action_type == "github.create_issue":
            payload = self._issue_payload(action_input)
            endpoint = f"/repos/{resource}/issues"
        elif action_type == "github.create_pull_request":
            payload = self._pull_request_payload(action_input)
            endpoint = f"/repos/{resource}/pulls"
        elif action_type == "github.add_comment":
            self._reject_unknown_fields(action_input, {"issue_number", "body"})
            number = self._positive_integer(action_input, "issue_number")
            payload = self._comment_payload(action_input)
            endpoint = f"/repos/{resource}/issues/{number}/comments"
        elif action_type == "github.add_labels":
            self._reject_unknown_fields(action_input, {"issue_number", "labels"})
            number = self._positive_integer(action_input, "issue_number")
            payload = {"labels": self._string_list(action_input, "labels")}
            endpoint = f"/repos/{resource}/issues/{number}/labels"
        elif action_type == "github.request_review":
            self._reject_unknown_fields(
                action_input, {"pull_number", "reviewers", "team_reviewers"}
            )
            number = self._positive_integer(action_input, "pull_number")
            payload = {
                field: self._string_list(action_input, field, allow_empty=True)
                for field in ("reviewers", "team_reviewers") if field in action_input
            }
            if not any(payload.values()):
                raise GitHubExecutorError("reviewers or team_reviewers must be non-empty")
            endpoint = f"/repos/{resource}/pulls/{number}/requested_reviewers"
        else:
            raise GitHubExecutorError(f"unsupported GitHub action_type: {action_type}")

        return method, self._api_url + endpoint, payload, action_type, resource

    @staticmethod
    def _positive_integer(value: dict[str, Any], field: str) -> int:
        number = value.get(field)
        if type(number) is not int or number <= 0:
            raise GitHubExecutorError(f"{field} must be a positive integer")
        return number

    @staticmethod
    def _string_list(
        value: dict[str, Any], field: str, *, allow_empty: bool = False
    ) -> list[str]:
        items = value.get(field)
        if (
            not isinstance(items, list)
            or (not items and not allow_empty)
            or not all(isinstance(item, str) and item.strip() for item in items)
        ):
            raise GitHubExecutorError(f"{field} must be an array of non-empty strings")
        return items

    def _comment_payload(self, value: dict[str, Any]) -> dict[str, Any]:
        """Build a thread-level comment for an issue or PR, not an inline review."""
        body = self._required_string(value, "body")
        if not body.strip() or len(body) > 65_536:
            raise GitHubExecutorError("body must contain 1 to 65,536 characters")
        return {"body": body}

    @staticmethod
    def _required_string(value: dict[str, Any], field: str) -> str:
        result = value.get(field)
        if not isinstance(result, str) or not result:
            raise GitHubExecutorError(f"{field} must be a non-empty string")
        return result

    def _issue_payload(self, value: dict[str, Any]) -> dict[str, Any]:
        allowed = {"title", "body", "labels"}
        self._reject_unknown_fields(value, allowed)
        payload: dict[str, Any] = {"title": self._required_string(value, "title")}
        if "body" in value:
            if not isinstance(value["body"], str):
                raise GitHubExecutorError("input.body must be a string")
            payload["body"] = value["body"]
        if "labels" in value:
            labels = value["labels"]
            if not isinstance(labels, list) or not all(
                isinstance(label, str) for label in labels
            ):
                raise GitHubExecutorError("input.labels must be an array of strings")
            payload["labels"] = labels
        return payload

    def _pull_request_payload(self, value: dict[str, Any]) -> dict[str, Any]:
        allowed = {"title", "head", "base", "body", "draft"}
        self._reject_unknown_fields(value, allowed)
        payload: dict[str, Any] = {
            "title": self._required_string(value, "title"),
            "head": self._required_string(value, "head"),
            "base": self._required_string(value, "base"),
        }
        if "body" in value:
            if not isinstance(value["body"], str):
                raise GitHubExecutorError("input.body must be a string")
            payload["body"] = value["body"]
        if "draft" in value:
            if not isinstance(value["draft"], bool):
                raise GitHubExecutorError("input.draft must be a boolean")
            payload["draft"] = value["draft"]
        return payload

    @staticmethod
    def _reject_unknown_fields(value: dict[str, Any], allowed: set) -> None:
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise GitHubExecutorError(f"unsupported input fields: {', '.join(unknown)}")

    @staticmethod
    def _sanitize_result(
        response: dict[str, Any] | list[Any], action_type: str, resource: str
    ) -> dict[str, Any]:
        result = {"action_type": action_type, "resource": resource}
        if action_type == "github.merge_pull_request":
            result["merged"] = response.get("merged") is True
            sha = response.get("sha")
            if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                result["sha"] = sha
            return result
        if action_type == "github.add_labels":
            if not isinstance(response, list) or not all(
                isinstance(label, dict) for label in response
            ):
                raise GitHubExecutorError("GitHub returned an invalid labels response")
            result["labels"] = [
                {field: label[field] for field in ("id", "name", "color")
                 if field in label and type(label[field]) in (str, int)}
                for label in response
            ]
            return result
        if not isinstance(response, dict):
            raise GitHubExecutorError("GitHub returned a non-object response")
        for field in ("id", "number", "html_url", "url", "state"):
            if field in response and type(response[field]) in (str, int):
                result[field] = response[field]
        return result


class GitHubAppExecutorAdapter:
    """Execute a narrow set of GitHub writes from a verified Tempus permit using GitHub App credentials."""

    def __init__(
        self,
        executor_db: str,
        executor_keyfile: str,
        trusted_gate_id: str,
        trusted_tenant_id: str,
        credentials: GitHubAppCredentials,
        api_url: str = "https://api.github.com",
        transport: GitHubTransport | None = None,
        executor_pool_size: int = 8,
        gate_db: str | None = None,
        *,
        push_branch_prefix: str = DEFAULT_BRANCH_PREFIX,
        publisher: BundlePublisher | None = None,
        remote_url_for: Callable[[str], str] | None = None,
    ):
        self._adapter = GitHubAppActionAdapter(
            credentials=credentials,
            api_url=api_url,
            transport=transport,
            push_branch_prefix=push_branch_prefix,
            publisher=publisher,
            remote_url_for=remote_url_for,
        )
        runtime_kwargs: dict[str, Any] = {
            "executor_db": executor_db,
            "executor_keyfile": executor_keyfile,
            "trusted_gate_id": trusted_gate_id,
            "trusted_tenant_id": trusted_tenant_id,
            "executor_pool_size": executor_pool_size,
        }
        if gate_db is not None:
            if "gate_db" in inspect.signature(ExecutorRuntime.__init__).parameters:
                runtime_kwargs["gate_db"] = gate_db
            else:
                raise GitHubExecutorError(
                    "gate_db is configured for revocation verification, but the underlying ExecutorRuntime does not support it"
                )
        self._runtime = ExecutorRuntime(**runtime_kwargs)
        self._gate_db = gate_db

    def execute(self, permit_json: str, *, bundle_path: str | Path | None = None) -> str:
        """Consume a permit, perform exactly its GitHub action, and sign the outcome.

        ``bundle_path`` is required for github.push_branch; the permit binds its sha256.
        """
        artifacts = {"bundle": bundle_path} if bundle_path else None
        return self._runtime.execute_permit(
            permit_json,
            PermitBoundActionAdapter(self._adapter, permit_json, self._gate_db, artifacts),
        )

    execute_permit = execute

    def recover_incomplete(self, older_than_seconds: int = 0) -> str:
        """Mark stale STARTED executions UNKNOWN without replaying GitHub writes."""
        return self._runtime.raw_executor.recover_incomplete(older_than_seconds)

    def get_execution_state(self, authorization_id: str) -> str:
        """Return the executor's signed local state for an authorization."""
        return self._runtime.raw_executor.get_execution_state(authorization_id)
