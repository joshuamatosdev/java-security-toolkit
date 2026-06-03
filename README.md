# Project Glyptodon

A buildable security-architecture reference.

> Defense in depth, plated layer by layer.

A runnable Java 21 reference for platform security patterns. Each module is a
small Spring/Gradle project that turns one security design decision into code,
tests, and ADR-backed documentation.

This repository is intentionally neutral. The examples use fictional tenants,
organizations, and documents so the patterns can be studied without exposing a
real production system.

## Table of Contents

- [Quick Start](#quick-start)
- [Status](#status)
- [What Is Included](#what-is-included)
- [Architecture Posture](#architecture-posture)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)

## Quick Start

Requirements:

- JDK 21
- Docker, for Testcontainers-backed integration tests

Build and test everything:

```bash
./gradlew build
```

Run one module:

```bash
./gradlew :tenant-isolation:test
./gradlew :layered-authorization:test
```

The test suite starts PostgreSQL containers where a pattern depends on real
database behavior.

## Status

| Area | Status |
|---|---|
| Build | `./gradlew build` |
| Java | 21 |
| Framework | Spring Boot 3.5.x |
| License | Apache License 2.0 |
| Current modules | `shared`, `tenant-isolation`, `layered-authorization` |

## What Is Included

```text
modules/
|-- shared/                  # typed cross-module identifiers
|-- tenant-isolation/        # tenant placement, session binding, PostgreSQL RLS
|-- layered-authorization/   # coarse request gate + fine-grained policy
|-- docs/
|   |-- adr/                 # architecture decision records
|   `-- GLOSSARY.md          # shared vocabulary
|-- gradle/                  # version catalog and wrapper files
|-- CONVENTIONS.md           # repository rules
`-- README.md
```

### `shared`

The cross-module identity kernel. It owns typed identifiers used by more than
one module:

- `TenantId`
- `OrganizationId`
- `ResourceId`

### `tenant-isolation`

Layer 5 data isolation. The module supports three configured tenant placement
modes:

- `id`: shared tables, `tenant_id`, signed PostgreSQL session claim, forced RLS
- `schema`: one PostgreSQL schema per tenant, with signed tenant claim binding
- `database`: one JDBC pool per tenant database, with signed tenant claim binding

The default path demonstrates non-superuser runtime roles, a read-only
system-ops pool, database-owned UUIDv7 identifiers, and build-breaking audits
for unsafe pool identities.

See [tenant-isolation/README.md](tenant-isolation/README.md).

### `layered-authorization`

Layer 2 authorization. The module combines:

- a deny-by-default request gate
- a typed principal and immutable request context
- a pure resource-aware policy
- deny-overrides rules
- audit records for every allow and deny
- PostgreSQL-backed document facts with database-owned UUIDv7 identifiers

See [layered-authorization/README.md](layered-authorization/README.md).

## Architecture Posture

The repository demonstrates a five-layer posture where controls are structural
and deny-by-default.

| Layer | Concern | Module |
|---|---|---|
| 1. Identity / AuthN | OIDC, PKCE, MFA, step-up | planned |
| 2. Authorization | coarse route gate plus fine-grained resource policy | `layered-authorization` |
| 3. Secrets / config | no production secret in source or image | documented in ADR-0001 |
| 4. Transport / runtime | perimeter, headers, actuator lockdown | planned |
| 5. Data | tenant placement, least-privilege roles, RLS | `tenant-isolation` |
| 5. Supply chain | SBOM, signing, dependency and image checks | planned |
| Cross-cutting | crypto agility and migration strategy | planned |

## Documentation

- [Conventions](CONVENTIONS.md)
- [Glossary](docs/GLOSSARY.md)
- [ADR index](docs/adr/README.md)
- [ADR-0001: Five-layer security posture](docs/adr/0001-five-layer-security-posture.md)
- [ADR-0002: Tenant isolation with RLS session binding](docs/adr/0002-tenant-isolation-rls-session-binding.md)
- [ADR-0003: Layered authorization](docs/adr/0003-layered-authorization.md)

## Development

Useful commands:

```bash
./gradlew test
./gradlew build
./gradlew :tenant-isolation:test --tests "*SchemaIsolationModeIntegrationTest"
./gradlew :layered-authorization:test --tests "*DocumentControllerSecurityTest"
```

Repository rules:

- One module demonstrates one pattern.
- A module must build from a clean clone with only JDK 21 and Docker.
- Shared types live in `shared` once, never duplicated.
- ADRs are append-only decision records.
- Examples use neutral fictional values such as `acme` and `globex`.

## License

Apache License 2.0 — free to use and modify; attribution is required.
Redistributions must carry the [`NOTICE`](NOTICE). See [LICENSE](LICENSE).
