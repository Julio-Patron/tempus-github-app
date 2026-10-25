# Security Policy

## Supported Versions

| Version | Status |
|---|---|
| `0.1.x` | Current beta source line |
| `< 0.1` | There is no earlier release |

No stable release has been published yet. Security fixes are developed on `main` and
will be included in the next tagged beta.

This app follows the supported `tempus-ddb` line declared in `pyproject.toml`.
Vulnerabilities in the core belong to that project.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly.

- Open a private security advisory on GitHub: https://github.com/Julio-Patron/tempus-github-app/security/advisories/new

Please do **not** open a public issue for security vulnerabilities.

We aim to acknowledge a report within 48 hours and will coordinate disclosure and a fix
privately.

## Current Security Boundary

- The project is local-first. The SQLite databases are tamper-evident, not encrypted, and
  not independently protected against full deletion or rollback.
- Plaintext keyfiles are supported for local evaluation only. The GitHub App private key
  and installation tokens exist only in the executor process; an agent that obtains either
  one can bypass Tempus. Production gate signing should use the core's Vault Transit
  signer. Signed rotation and revocation are implemented in `tempus-ddb`, but operators
  must distribute revocation state before relying on multiple executor instances.
- The executor is a single-instance adapter for the GitHub actions it implements.
  An executor result of `UNKNOWN` requires manual reconciliation and must never be retried
  automatically.
- Host permissions, backups, credential isolation, network policy, and downstream service
  controls remain operator responsibilities.

Read the core threat model before using Tempus for any high-impact action:
https://github.com/Julio-Patron/tempus-ddb/blob/main/THREAT_MODEL.md
