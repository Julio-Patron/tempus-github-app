"""Command line interface for Tempus GitHub App Executor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from tempus_ddb.executor_runtime import UnknownExecutionError

from . import __version__
from .credentials import GitHubAppCredentials
from .executor import GitHubAppExecutorAdapter
from .git_push import DEFAULT_BRANCH_PREFIX

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _read_permit(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _get_env_int(name: str, default: int | None = None) -> int | None:
    val = os.environ.get(name)
    if val is not None and val.strip():
        try:
            return int(val.strip())
        except ValueError:
            return default
    return default


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="tempus-github-app-executor",
        description="Execute GitHub writes bound to a signed Tempus permit using GitHub App credentials",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--permit",
        default=os.environ.get("TEMPUS_PERMIT"),
        help="Path to signed permit JSON file, or '-' for stdin (env: TEMPUS_PERMIT)",
    )
    parser.add_argument(
        "--executor-db",
        default=os.environ.get("TEMPUS_EXECUTOR_DB"),
        help="Path to executor SQLite database (env: TEMPUS_EXECUTOR_DB)",
    )
    parser.add_argument(
        "--executor-keyfile",
        default=os.environ.get("TEMPUS_EXECUTOR_KEYFILE"),
        help="Path to executor Ed25519 keys JSON (env: TEMPUS_EXECUTOR_KEYFILE)",
    )
    parser.add_argument(
        "--gate-id",
        default=os.environ.get("TEMPUS_GATE_ID"),
        help="Trusted Gate public key in hex (env: TEMPUS_GATE_ID)",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("TEMPUS_TENANT_ID"),
        help="Tenant ID string (env: TEMPUS_TENANT_ID)",
    )
    parser.add_argument(
        "--gate-db",
        default=os.environ.get("TEMPUS_GATE_DB"),
        help="Optional path to Tempus Gate SQLite DB for revocation verification (env: TEMPUS_GATE_DB)",
    )

    # GitHub App credentials
    parser.add_argument(
        "--app-client-id",
        default=os.environ.get("GITHUB_APP_CLIENT_ID"),
        help="GitHub App Client ID, e.g. Iv1.xxx (env: GITHUB_APP_CLIENT_ID)",
    )
    parser.add_argument(
        "--app-private-key",
        default=os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH"),
        help="Path to GitHub App RSA private key .pem (env: GITHUB_APP_PRIVATE_KEY_PATH)",
    )
    parser.add_argument(
        "--app-private-key-base64",
        default=os.environ.get("GITHUB_APP_PRIVATE_KEY_BASE64"),
        help="Base64-encoded GitHub App RSA private key .pem (env: GITHUB_APP_PRIVATE_KEY_BASE64)",
    )
    parser.add_argument(
        "--installation-id",
        type=int,
        default=_get_env_int("GITHUB_APP_INSTALLATION_ID"),
        help="GitHub App installation ID (env: GITHUB_APP_INSTALLATION_ID)",
    )
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_APP_REPOSITORY"),
        help="Target repository in owner/repo format (env: GITHUB_APP_REPOSITORY)",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        help="GitHub API base URL (env: GITHUB_API_URL, default: https://api.github.com)",
    )
    parser.add_argument(
        "--executor-pool-size",
        type=int,
        default=_get_env_int("TEMPUS_EXECUTOR_POOL_SIZE", 8),
        help="Maximum pooled SQLite connections (env: TEMPUS_EXECUTOR_POOL_SIZE, default: 8)",
    )
    parser.add_argument(
        "--bundle",
        default=os.environ.get("TEMPUS_BUNDLE"),
        help="Git bundle for github.push_branch; the permit binds its sha256 (env: TEMPUS_BUNDLE)",
    )
    parser.add_argument(
        "--push-branch-prefix",
        default=os.environ.get("TEMPUS_PUSH_BRANCH_PREFIX", DEFAULT_BRANCH_PREFIX),
        help=(
            "Only branches under this namespace can be pushed "
            f"(env: TEMPUS_PUSH_BRANCH_PREFIX, default: {DEFAULT_BRANCH_PREFIX})"
        ),
    )

    args = parser.parse_args(argv)

    # Validate required arguments with informative errors
    missing = []
    if not args.permit:
        missing.append("--permit (or TEMPUS_PERMIT)")
    if not args.executor_db:
        missing.append("--executor-db (or TEMPUS_EXECUTOR_DB)")
    if not args.executor_keyfile:
        missing.append("--executor-keyfile (or TEMPUS_EXECUTOR_KEYFILE)")
    if not args.gate_id:
        missing.append("--gate-id (or TEMPUS_GATE_ID)")
    if not args.tenant_id:
        missing.append("--tenant-id (or TEMPUS_TENANT_ID)")
    if not args.app_client_id:
        missing.append("--app-client-id (or GITHUB_APP_CLIENT_ID)")
    if not args.app_private_key and not args.app_private_key_base64:
        missing.append("--app-private-key (or GITHUB_APP_PRIVATE_KEY_PATH / GITHUB_APP_PRIVATE_KEY_BASE64)")
    if args.installation_id is None:
        missing.append("--installation-id (or GITHUB_APP_INSTALLATION_ID)")
    if not args.repository:
        missing.append("--repository (or GITHUB_APP_REPOSITORY)")

    if missing:
        print(
            f"Error: Missing required arguments: {', '.join(missing)}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    try:
        credentials = GitHubAppCredentials(
            client_id=args.app_client_id,
            private_key_path=args.app_private_key,
            private_key_pem=args.app_private_key_base64,
            installation_id=args.installation_id,
            repository=args.repository,
            api_url=args.api_url,
        )

        adapter = GitHubAppExecutorAdapter(
            executor_db=args.executor_db,
            executor_keyfile=args.executor_keyfile,
            trusted_gate_id=args.gate_id,
            trusted_tenant_id=args.tenant_id,
            credentials=credentials,
            api_url=args.api_url,
            executor_pool_size=args.executor_pool_size,
            gate_db=args.gate_db,
            push_branch_prefix=args.push_branch_prefix,
        )

        permit_content = _read_permit(args.permit)
        outcome = adapter.execute(permit_content, bundle_path=args.bundle)
        print(outcome)
    except UnknownExecutionError as exc:
        print(exc.observation, file=sys.stderr)
        raise SystemExit(2) from exc
    except Exception as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
