# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | No |

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use GitHub's private vulnerability reporting on this repository
(Security → Advisories → Report a vulnerability). Include:

- affected version and operating system,
- steps to reproduce,
- expected and observed behaviour,
- whether the database, a backup, or the running process is involved,
- any proof-of-concept code or logs (never include real credentials).

You can expect an acknowledgement within seven days. This is a personal
portfolio project, so fixes are best-effort and there is no bug bounty.

## Scope

In scope:

- cryptographic design and implementation in `CryptoService`,
- authentication, lockout and session handling,
- SQLite schema, queries and file permissions,
- plaintext exposure through the UI or clipboard.

Out of scope:

- attacks that require the user's OS account or JVM to be compromised,
- denial of service by deleting the database,
- weak master passwords chosen by the user,
- the absence of features listed as known limitations in the README,
- social engineering.

## Safe harbour

Good-faith research on your own copy of the application is welcome. Do not test
against other people's vaults or devices.
