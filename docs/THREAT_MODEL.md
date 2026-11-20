# Threat model — Vault 1.1

This document describes what Vault protects, from whom, and what it explicitly
does not protect. It is intentionally short enough to review in one sitting.

## 1. Scope

In scope:

- the JavaFX application and its services,
- the local SQLite database and its side files (`-wal`, `-shm`),
- the clipboard hand-off and the in-memory vault key.

Out of scope:

- the operating system, JVM, JavaFX and SQLite implementations,
- the build and release infrastructure (covered separately by CI),
- other applications on the machine.

## 2. Assets

| Asset | Sensitivity | Where it lives |
| --- | --- | --- |
| Master password | Critical | User's memory; transient `char[]` |
| Vault key | Critical | RAM only, zeroed on lock |
| Entry passwords and notes | Critical | AES-GCM ciphertext in SQLite |
| Auth hash and salt | High | `users` table |
| Titles, usernames, URLs, categories | Medium | Plaintext in `vault_entries` |
| Database file | High | OS application-data directory |

## 3. Trust boundaries

```
┌────────────── user ──────────────┐
│ keyboard, screen, clipboard      │
└───────────────┬──────────────────┘
                │
┌───────────────▼──────────────────┐
│ JavaFX controllers               │  untrusted input: every field
│   validation, formatting         │
└───────────────┬──────────────────┘
                │ typed calls
┌───────────────▼──────────────────┐
│ Services                         │  security policy lives here
│ Auth / Crypto / Session / Audit  │
└───────────────┬──────────────────┘
                │ SQL + ciphertext
┌───────────────▼──────────────────┐
│ SQLite file (0600)               │  attacker with file write = game over
└──────────────────────────────────┘
```

The important boundary is between **controllers** and **services**. Controllers
are allowed to be wrong about presentation; services must fail closed. Services
do not import JavaFX, so their behaviour is unit-testable.

## 4. Adversaries considered

1. **Offline thief** — steals the laptop or a backup of the application-data
   directory, then reads the SQLite file on another machine.
2. **Other local OS user** — can read files only if permissions allow it.
3. **Malware as the same user** — can read process memory, keystrokes and files.
4. **Physical access** — can use the unlocked app, copy the clipboard, or modify
   the database.
5. **Network attacker** — no network communication exists; this is out of scope by
   construction.

## 5. STRIDE summary

| Threat | Example | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Fake login screen / wrong user | Local process only; DB user identity is a UUID | A compromised desktop can spoof anything |
| Tampering | Flip a ciphertext byte | AES-GCM authentication tag; fail closed | Attacker can delete entries or restore an old DB (DoS/replay) |
| Repudiation | Deny changing an entry | No audit log | Local app, not a multi-user system |
| Information disclosure | Read the DB file | AES-256-GCM; 0600/0700 permissions; key never on disk | Metadata is plaintext; memory/clipboard exposure |
| Denial of service | Delete the DB, lock the account | Lockout is time-bounded; DB is local | No backup/restore yet |
| Elevation of privilege | Swap one entry's ciphertext into another | GCM detects modification, not context swap | A writer can cause wrong-password display for an entry |
| Brute force | Guess the master password offline | 600k PBKDF2-SHA512, 32-byte salt, strong-password policy | Weak master passwords remain weak |
| Username enumeration | Time the login response | PBKDF2 burn for unknown users | Lockout state still reveals a local account exists |
| Clipboard leakage | Another app reads the clipboard | Cleared after 60 s if unchanged | Clipboard managers may have copied it already |
| Shoulder surfing | Password left on screen | Masked by default; reveal auto-hides after 30 s | Screenshots/recording |

## 6. Cryptographic choices

- **AES-256-GCM** provides confidentiality and integrity in one pass. A fresh
  96-bit IV is generated for every encryption operation. Reusing an IV with the
  same key would be catastrophic, so IVs are never derived from counters or
  content.
- **PBKDF2-HMAC-SHA512, 600,000 iterations** is used for the authentication hash.
  The vault key uses a second PBKDF2 pass with the salt concatenated with a
  domain-separation label. This guarantees that the stored auth hash is not the
  encryption key.
- **`SecureRandom`** is the only randomness source. The password generator uses
  `nextInt(bound)`, which is unbiased, and explicitly includes each selected
  character class.
- **`MessageDigest.isEqual`** is used for hash comparison to avoid early-exit
  timing leaks.

## 7. Assumptions

- The user chooses a strong, unique master password.
- The operating system and JVM are not compromised.
- Full-disk encryption is recommended but not required for Vault's guarantees.
- The user's OS account is not shared with an adversary.
- The database is not restored from an untrusted backup.

## 8. Verification evidence

- 39 automated tests, including jqwik properties over arbitrary plaintext and
  generator options.
- Tamper tests assert `AEADBadTagException` on modified ciphertext.
- Lockout tests assert the exact 5-attempt/30-minute state transitions.
- Permission tests assert `0700` on the directory and `0600` on the database.
- The suite runs with `./mvnw verify`; CI builds the JAR on Linux, macOS and Windows with JDK 21.
- `git log` and this document are the design record; there is no formal proof.

## 9. Review triggers

Re-open this model when any of the following change:

- the database schema or KDF parameters,
- the sync/export feature (new data flows),
- the clipboard or windowing behaviour,
- a new dependency with native code,
- the threat landscape for desktop password managers.
