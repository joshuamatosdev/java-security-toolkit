# Contributing

Thanks for considering a contribution. This toolkit is intentionally small. One module demonstrates one security pattern. Every pattern must stay runnable. Even from a clean clone.

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
./gradlew :edge:test
```

## Contribution Rules

- Keep examples neutral. Use fictional values only. Like `acme`, `globex`, `example.com`. And random test UUIDs.
- Never commit these. Secrets. Real tenant or customer data. Internal hostnames. Production identifiers. Private keys. Tokens. Credentials. `.env` files.
- Keep module boundaries clear. Cross-module identity types belong in `shared`. Module-specific behavior stays in its module.
- Did a change touch these? Add or update tests. A security boundary. An authorization decision. A tenant boundary. A crypto seam. A supply-chain check. A public contract.
- ADRs are append-only decision records. Did a security decision change? Update or add an ADR.
- Keep comments useful. Prefer comments that explain the why. Why a boundary exists. Why a test matters.

## Pull Request Checklist

Before opening a pull request:

```bash
./gradlew test
git diff --check
```

Also review:

- [Public release checklist](docs/maintainer/PUBLIC_RELEASE_CHECKLIST.md)
- [Security policy](SECURITY.md)
- [Conventions](CONVENTIONS.md)

## Dependency Changes

A dependency update must explain itself. Say why the update is needed. Then say what it affects. Runtime behavior. Test-only behavior. Vulnerability posture. Licensing. Build reproducibility.

## Security Reports

Never post exploitable details publicly. Not in issues. Not in pull requests. Follow [SECURITY.md](SECURITY.md) for private reporting.
