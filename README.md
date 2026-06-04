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
| Current modules | `shared`, `tenant-isolation`, `layered-authorization`, `edge-perimeter`, `supply-chain`, `crypto-agility` |

## What Is Included

```text
modules/
|-- shared/                  # typed cross-module identifiers
|-- tenant-isolation/        # tenant placement, session binding, PostgreSQL RLS
|-- layered-authorization/   # coarse request gate + fine-grained policy
|-- edge-perimeter/          # BFF edge: dual credential planes, headers, CORS, CSRF
|-- supply-chain/            # build trust horizon: SBOM, dep-scan, wrapper + base-image pin
|-- crypto-agility/          # one signer seam, algorithm registry, reserved post-quantum slot
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

### `edge-perimeter`

Layers 1 and 4: the backend-for-frontend edge. The module separates two credential
planes into two ordered security chains:

- a browser plane authenticated by OIDC Authorization-Code + PKCE login (session
  cookie), with CSRF, a credentialed CORS allow-list, deny-by-default routing, and
  security headers on every response
- a stateless service plane (`/api/service/**`) authenticated by bearer JWT, with no
  cookie, no CSRF, and no CORS surface

The planes are kept disjoint by a filter that strips a browser-supplied
`Authorization` header, and the route map registers narrow role exceptions before the
broad admin gate. Pure WebFlux + Spring Security; the tests need only JDK 21.

See [edge-perimeter/README.md](edge-perimeter/README.md).

### `supply-chain`

The cross-cutting supply-chain layer: the build's trust horizon. Every dependency, the build tool,
and the runtime base image is code that executes, so the module pins and verifies each:

- a Gradle wrapper pinned by `distributionSha256Sum`
- a CycloneDX SBOM emitted on build, with an integrity gate that asserts on the real generated bill
- an OWASP dependency scan (CI / on-demand; `failBuildOnCVSS = 7.0`)
- a base-image-pin policy enforced by a test that fails on any floating `FROM` tag
- documented activation for the repo-global anchors (dependency-verification metadata, lockfile)

Built from the verified supply-chain gaps in the real platform (the gateway shipped no
dependency-verification metadata; a backend left only a dry-run seed). Tests need only JDK 21.

See [supply-chain/README.md](supply-chain/README.md).

### `crypto-agility`

The cross-cutting crypto-strategy layer. Every algorithm-specific decision sits behind one
`SignatureProvider` interface, providers are resolved from a registry keyed by algorithm, and keys
are referenced by versioned handles that sign without exposing private material:

- an algorithm registry (`SignatureAlgorithm`) as the single authority for algorithm + wire id
- a provider seam and an immutable registry that rejects duplicate algorithms
- a `DocumentSigner` call site that seals and verifies while naming no algorithm
- a reserved, exercised post-quantum slot (`ML-DSA-44`) behind the same interface

The agility property — an algorithm swap leaves call sites unchanged — is proven by driving one
call site across every algorithm. Plain Java; tests need only JDK 21.

See [crypto-agility/README.md](crypto-agility/README.md).

## Architecture Posture

The repository demonstrates a five-layer posture where controls are structural
and deny-by-default.

| Layer | Concern | Module |
|---|---|---|
| 1. Identity / AuthN | OIDC, PKCE, MFA, step-up | `edge-perimeter` |
| 2. Authorization | coarse route gate plus fine-grained resource policy | `layered-authorization` |
| 3. Secrets / config | no production secret in source or image | documented in ADR-0001 |
| 4. Transport / runtime | perimeter, headers, actuator lockdown | `edge-perimeter` |
| 5. Data | tenant placement, least-privilege roles, RLS | `tenant-isolation` |
| 5. Supply chain | SBOM, dependency + wrapper + base-image verification | `supply-chain` |
| Cross-cutting | crypto agility and migration strategy | `crypto-agility` |

## Documentation

- [Conventions](CONVENTIONS.md)
- [Glossary](docs/GLOSSARY.md)
- [ADR index](docs/adr/README.md)
- [ADR-0001: Five-layer security posture](docs/adr/0001-five-layer-security-posture.md)
- [ADR-0002: Tenant isolation with RLS session binding](docs/adr/0002-tenant-isolation-rls-session-binding.md)
- [ADR-0003: Layered authorization](docs/adr/0003-layered-authorization.md)
- [ADR-0004: Edge perimeter with dual credential planes](docs/adr/0004-edge-perimeter-dual-plane.md)
- [ADR-0005: Supply-chain trust horizon](docs/adr/0005-supply-chain-trust-horizon.md)
- [ADR-0006: Cryptographic agility](docs/adr/0006-crypto-agility-provider-seam.md)

## Development

Useful commands:

```bash
./gradlew test
./gradlew build
./gradlew :tenant-isolation:test --tests "*SchemaIsolationModeIntegrationTest"
./gradlew :layered-authorization:test --tests "*DocumentControllerSecurityTest"
./gradlew :edge-perimeter:test --tests "*RouteAuthorizationTest"
./gradlew :supply-chain:test --tests "*SbomIntegrityTest"
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
