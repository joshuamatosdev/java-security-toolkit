# Contributing

Thanks for considering a contribution. Project Glyptodon is intentionally small:
one module demonstrates one security pattern, and every pattern should remain
runnable from a clean clone.

## Setup

Requirements:

- JDK 21
- Docker, for Testcontainers-backed integration tests

Run the full build:

```bash
./gradlew build
```

Run one module:

```bash
./gradlew :tenant-isolation:test
./gradlew :edge-perimeter:test
```

## Contribution Rules

- Keep examples neutral. Use fictional values such as `acme`, `globex`,
  `example.com`, and random test UUIDs.
- Do not commit secrets, real tenant or customer data, internal hostnames,
  production identifiers, private keys, tokens, credentials, or `.env` files.
- Keep module boundaries clear. Shared cross-module identity types belong in
  `shared`; module-specific behavior belongs in the module that demonstrates it.
- Add or update tests when a change affects a security boundary, authorization
  decision, tenant boundary, crypto seam, supply-chain check, or public contract.
- ADRs are append-only decision records. Update or add a new ADR when a security
  decision changes.
- Keep comments useful. Prefer rationale that explains why a boundary exists or
  why a test matters.

## Pull Request Checklist

Before opening a pull request:

```bash
./gradlew test
git diff --check
```

Also review:

- [Public release checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Conventions](CONVENTIONS.md)

## Dependency Changes

Dependency updates should explain why the update is needed and whether it affects
runtime behavior, test-only behavior, vulnerability posture, licensing, or build
reproducibility.

## Security Reports

Do not disclose exploitable details in public issues or pull requests. Follow
[SECURITY.md](SECURITY.md) for private reporting.
