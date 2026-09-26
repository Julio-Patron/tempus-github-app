<div align="center">

# Tempus GitHub App

### Credential-Isolated Mediated Executor and GitHub App Integration for Tempus DDB

**Short-lived installation tokens · Zero-leak credential boundary · Atomic single-use permit consumption · Cryptographic receipts**

<p align="center">
  <a href="https://github.com/elbuilder77/tempus-github-app/actions/workflows/ci.yml"><img src="https://github.com/elbuilder77/tempus-github-app/actions/workflows/ci.yml/badge.svg" alt="CI Build" /></a>
  <a href="https://github.com/elbuilder77/tempus-ddb"><img src="https://img.shields.io/badge/ecosystem-tempus--ddb-blue.svg" alt="Tempus DDB Ecosystem" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" /></a>
  <a href="https://elbuilder77.github.io/tempus-ddb/"><img src="https://img.shields.io/badge/docs-interactive%20trace-orange.svg" alt="Interactive Trace Docs" /></a>
</p>

</div>

---

## 🔒 Overview

**Tempus GitHub App** decouples GitHub privileged operations from autonomous AI agents. Rather than provisioning personal access tokens (PATs) directly to agents or runners:

1. **Requesting Agents** sign an **Intent** declaring the requested repository action without holding GitHub credentials.
2. **Tempus Gate** evaluates cryptographic tenant policy and grants an expiring, single-use signed **Permit**.
3. **Tempus GitHub App Executor** validates the permit, atomically consumes it, and mints short-lived (1-hour), installation- and repository-scoped GitHub App tokens using an RSA private key.
4. **Execution Outcomes** are signed and recorded into the Tempus immutable decision ledger.

Neither the GitHub App private key nor ephemeral installation tokens ever leak to the requesting agent or execution receipts.

```text
┌─────────────────┐       1. Signed Intent        ┌──────────────────┐
│ Requesting Agent│ ────────────────────────────► │   Tempus Gate    │
│  (No GitHub key)│ ◄──────────────────────────── │ (Signed Policies)│
└────────┬────────┘       2. Signed Permit        └──────────────────┘
         │
         │ 3. Present Permit
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 Tempus GitHub App Mediated Executor                 │
│                                                                     │
│  4. Atomically consume permit & verify Gate signature               │
│  5. Mint ephemeral RS256 JWT from RSA private key (.pem)            │
│  6. Exchange JWT for 1-hour repository-scoped installation token    │
│  7. Call GitHub REST API (Issues / Pull Requests)                   │
│  8. Dual-sign execution outcome (Zero credential leakage)           │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   │ 9. Immutable Trace Receipt
                                   ▼
                         ┌────────────────────┐
                         │    Tempus Trace    │
                         │ (Offline Auditable)│
                         └────────────────────┘
```

---

## ⚡ Installation

```bash
pip install -e .
# or with optional webhook server:
pip install -e ".[server]"
# or for running tests and development:
pip install -e ".[dev]"
```

Requires Python 3.10+, Git, and the stable Rust toolchain to build the pinned
`tempus-ddb` runtime. The dependency currently points to commit
`95e792be4dda22bf65963896a81191d0d0cef094` (0.5.2 source), which supports
`gate_db`; the published 0.5.1 runtime lacks that constructor argument.
Keep the source pin until a compatible release is published and verified.

---

## 🚀 Quick Usage

### 1. Configure the Executor
Ensure you have registered a GitHub App and installed it on your repository (see [docs/SETUP.md](docs/SETUP.md)).

You can configure credentials either via CLI arguments or environment variables (`.env` supported):

```bash
cp .env.example .env
# Edit .env with your App Client ID, private key path, installation ID, repository, and Gate ID
```

### 2. Execute a Signed Permit via CLI
Given a signed permit `permit.json` issued by the Tempus Gate for `github.create_issue`:

```bash
# Using CLI arguments:
tempus-github-app-executor \
  --permit permit.json \
  --executor-db executor.db \
  --executor-keyfile executor.keys.json \
  --gate-id <GATE_PUBLIC_KEY> \
  --tenant-id <TENANT_ID> \
  --app-client-id <APP_CLIENT_ID> \
  --app-private-key /path/to/private-key.pem \
  --installation-id 12345678 \
  --repository owner/repo

# Or with environment variables configured in .env:
tempus-github-app-executor --permit permit.json
```

Accepts `stdin` via `--permit -` for piping directly from `tempus request-action`.

### 3. Optional: Webhook Receiver Server

Run the FastAPI-based webhook receiver to securely verify GitHub webhook deliveries:

```bash
tempus-github-app-server --secret <WEBHOOK_SECRET> --port 8000
```

* `POST /webhook`: Validates `X-Hub-Signature-256` HMAC-SHA256 signature, dispatches events, and masks internal errors with generic responses.
* `GET /healthz`: Health check endpoint for container orchestrators.

### 4. Python SDK Integration

```python
from tempus_github_app import GitHubAppCredentials, GitHubAppExecutorAdapter

credentials = GitHubAppCredentials(
    client_id="Iv1.xxxx",
    private_key_path="secrets/app.pem",
    installation_id=12345678,
    repository="owner/repo",
)

executor = GitHubAppExecutorAdapter(
    executor_db="executor.db",
    executor_keyfile="executor.keys.json",
    trusted_gate_id=gate_public_key,
    trusted_tenant_id="tenant-1",
    credentials=credentials,
)

outcome_json = executor.execute(permit_json)
```

---

## 🛡️ Security Guarantees & Invariants

### Supported actions

All actions require an exact `owner/repository` resource in the signed intent.
Unknown input fields are rejected before requesting installation credentials.

| Action | Required input | Installation permission |
| --- | --- | --- |
| `github.create_issue` | `title` | `issues: write` |
| `github.create_pull_request` | `title`, `head`, `base` | `pull_requests: write` |
| `github.add_comment` | Positive integer `issue_number`, non-empty `body` (up to 65,536 characters) | `issues: write` |
| `github.add_labels` | Positive integer `issue_number`, non-empty list of non-empty `labels` | `issues: write` |
| `github.request_review` | Positive integer `pull_number`, at least one non-empty list of `reviewers` or `team_reviewers` | `pull_requests: write` |
| `github.merge_pull_request` | Positive integer `pull_number`, 40-character hexadecimal HEAD `sha`, explicit `merge_method` (`merge`, `squash`, `rebase`) | `contents: write` |
| `github.push_branch` | `branch` under the push namespace (default `agent/`), lowercase 40-hex `base_sha` and `tip_sha`, boolean `new_branch`, `bundle_sha256` of the git bundle, sorted unique `paths` (at most 1,000) | `contents: write` |

Comments are conversation-thread comments on issues or pull requests. Review
requests accept user logins and team slugs. Label outcomes include only label
IDs, names, and colors; comment and review-request outcomes retain only selected
resource metadata, excluding comment bodies and user profiles.

Merges accept optional string `commit_title` and `commit_message`. They succeed only
when GitHub explicitly returns boolean `merged: true`. Existing Apps must add
`contents: write`, and existing installations must accept the updated permissions.
Configure Gate policy to restrict merges to integration/release-manager identities
and require human approval for protected branches before issuing permits; this
executor does not configure that governance. See [merge setup](docs/SETUP.md#6-enable-governed-pull-request-merges).

#### Publishing an agent's commits (`github.push_branch`)

Agents commit locally and never hold a write credential. To publish, the agent's
side creates a git bundle from a **branch ref** (git refuses a bare SHA):

```bash
git bundle create agent.bundle <base_sha>..agent/fix-123
```

The signed intent binds the bundle's `sha256`, the exact `tip_sha`, the `base_sha`
and the list of changed `paths`. Before its single write, the executor:

1. rejects a bundle whose sha256 differs from the permit, before minting a token;
2. fetches only `base_sha` from GitHub (`--depth=1`), verifies and unbundles;
3. requires `tip_sha` to be a head of the bundle and a descendant of `base_sha`;
4. recomputes every path touched by the pushed commits (including changes a later
   commit reverts and files brought in by merges) and requires an exact match with `paths`;
5. pushes `tip_sha` to `refs/heads/<branch>` with `--force-with-lease`, pinned to
   "absent" when `new_branch` is true or to `base_sha` otherwise, so the update is a
   creation or a fast-forward from the signed state and nothing else.

Branches outside the push namespace (`--push-branch-prefix`, default `agent/`) are
rejected before credentials are requested, so `main` can never be pushed even if the
Gate policy is misconfigured. Git runs with no system/global configuration, hooks,
credential helpers or prompts, HTTPS only and redirects disabled; the installation token
travels only in an `http.<remote>.extraheader` setting scoped to the repository URL,
never in arguments or URLs. A push that times out or ends without a status line for the
branch is `UNKNOWN` and is never retried; failures before any upload (DNS, connection,
HTTP 4xx) are `FAILED`. The executor image must include `git` (the provided
`Dockerfile` installs it).

```bash
tempus-github-app-executor --permit permit.json --bundle agent.bundle
```

* **Zero Credential & Information Leakage**: The agent never receives GitHub tokens. The executor process handles authentication internally, and the webhook server sanitizes error responses to prevent internal detail disclosure.
* **Scope Minimization**: Tokens are generated on-demand with minimal repository and permission scope (`issues: write`, `pull_requests: write`, or `contents: write` for merges).
* **Redirect Shielding**: Enforces strict redirect blocking (`RejectRedirects`) on API calls to prevent credential forwarding to third-party endpoints.
* **Replay Protection**: The underlying Tempus permit is consumed atomically; replay attempts fail immediately without contacting GitHub.
* **Adapter Conformance**: Validated against the official `tempus_ddb.testing.AdapterConformanceHarness` conformance suite.

---

## Permit-bounded rate-limit retries

The executor supplies a per-execution `PermitContext` only from the runtime's
post-verification, post-consumption adapter callback. Its deadline comes from
the signed authorization (`expires_at` in microseconds, converted to UNIX seconds).
The same permit is never consumed again for a retry.

Configure `--gate-db` (or SDK `gate_db`) to enable up to three rate-limit retries.
Each attempt checks expiry and queries the Gate database read-only for permit
revocation, agent identity revocation, and an already committed outcome. Missing
databases, incompatible schemas, locks, and failed checks stop execution. Without
`gate_db`, requests receive a single attempt.

The transport respects `Retry-After` and primary rate-limit reset times. A
secondary limit without a wait header starts at 60 seconds, with exponential
backoff, following [GitHub's retry guidance](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).
It never shortens GitHub's wait to fit a permit. Expiry or revocation during a
wait prevents the next request. Socket timeouts are capped at 30 seconds and the
remaining budget; less than one second remaining stops the attempt rather than
rounding its timeout above the deadline. These are socket timeouts, not a guarantee
that an in-flight remote operation will finish before expiry.

Ordinary permission-denied responses and exhausted rate-limit budgets yield
`FAILED`. Network failures, timeouts, malformed success responses, and HTTP 5xx
yield `UNKNOWN` without automatic replay; reconciliation must use read-only calls.

Custom transports should accept `request(..., *, context: PermitContext | None = None)`
and enforce this contract. Legacy transports without that argument remain usable
without `gate_db`; configuring active revocation with such a transport fails closed.
The bundled bridge supports the SQLite revocation schema used by `tempus-ddb`;
it does not alter the installed runtime or its verification and signing logic.

## 🧪 Testing

Install test dependencies and run the test suite:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## 📄 License & Changelog

* [MIT License](LICENSE)
* [Changelog](CHANGELOG.md)

Part of the [Tempus DDB](https://github.com/elbuilder77/tempus-ddb) ecosystem.
