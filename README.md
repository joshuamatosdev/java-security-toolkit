# Bulwark

[![CI](https://github.com/joshuamatosdev/bulwark/actions/workflows/ci.yml/badge.svg)](https://github.com/joshuamatosdev/bulwark/actions/workflows/ci.yml)
[![Docs](https://github.com/joshuamatosdev/bulwark/actions/workflows/docs.yml/badge.svg)](https://joshuamatosdev.github.io/bulwark/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.org/projects/jdk/21/)

A production-oriented Java 21 security toolkit for multi-tenant SaaS systems.

Bulwark is built by Joshua Matos and DoctrineOne Industries. It turns
hard platform-security decisions into usable Java modules, executable tests, and
ADR-backed operating guidance for teams building multi-tenant applications.

Use it as production-oriented starting material: adopt modules directly, publish
them as internal Maven artifacts, or copy the patterns into an application with
the documented replacement points. The repository stays neutral and public-safe:
examples use fictional tenants, organizations, users, and documents.

## Quick Start

Requirements:

- JDK 21
- Docker, for Testcontainers-backed integration tests

Build and test everything:

```bash
./gradlew build
```

Publish the modules to your local Maven repository for application integration:

```bash
./gradlew publishToMavenLocal
```

Run focused modules:

```bash
./gradlew :tenant-isolation:test
./gradlew :tenant-isolation-spring-boot-starter:test
./gradlew :tenant-isolation-testkit:test
./gradlew :authorization:test
./gradlew :authorization-spring-boot-starter:test
./gradlew :authorization-testkit:test
./gradlew :authorization-showcase:test
./gradlew :edge:test
./gradlew :edge-spring-boot-starter:test
./gradlew :edge-testkit:test
./gradlew :supply-chain:test
./gradlew :supply-chain-testkit:test
./gradlew :crypto:test
./gradlew :crypto-spring-boot-starter:test
./gradlew :crypto-testkit:test
./gradlew :shared:test
./gradlew :shared-testkit:test
```

The test suite starts PostgreSQL containers where a pattern depends on real
database behavior.

## What You Can Use

```mermaid
flowchart LR
    Browser["Browser / SPA"] --> Edge["edge<br/>OIDC, PKCE, CORS, CSRF, headers"]
    Service["Service client"] --> Edge
    Edge --> Authz["authorization<br/>resource policy + audit"]
    Authz --> Tenant["tenant-isolation<br/>placement + signed session claim + RLS"]
    Tenant --> Postgres[("PostgreSQL")]
    Shared["shared<br/>typed identifiers"] --> Authz
    Shared --> Tenant
    Crypto["crypto<br/>provider seam + algorithm registry"] -. signs/verifies .-> Authz
    Supply["supply-chain<br/>SBOM + dependency/base-image checks"] -. verifies .-> Build["Build"]
```

| Module | Security pattern | What the tests prove |
|---|---|---|
| `shared` | Typed identity kernel | Tenant, organization, team, and resource IDs cannot be casually mixed as raw UUIDs. |
| `shared-testkit` | Typed identifier contracts | Adopters can reuse constructor, equality, and formatting contracts for shared identifier implementations. |
| `tenant-isolation` | Tenant placement, signed PostgreSQL session claims, organization scope, cross-tenant read entitlements, and RLS | Tenant context reaches the database boundary and isolation — including the organization dimension within a tenant and explicit read-only sharing across tenants — holds under real PostgreSQL behavior. |
| `tenant-isolation-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can import the tenant isolation configuration through one starter dependency. |
| `tenant-isolation-testkit` | Tenant context contracts | Adopters can prove context binding, clearing, and cross-tenant rejection without copying reference tests. |
| `authorization` | Fine-grained resource policy, deny-overrides, audit | Scope-layered policy, deny-overrides, and audit behavior are enforced from the same framework-free decision point. |
| `authorization-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can auto-wire the reference authorization service and policies. |
| `authorization-testkit` | Authorization policy contracts | Policy implementers can reuse allow, deny, mismatch, and audit-oriented contract checks. |
| `authorization-showcase` | Demonstration document API over the decision core (not published) | The coarse route gate, resource policy, PostgreSQL-backed ownership, and audit trail run together in a real Spring web application. |
| `edge` | Browser/service credential plane separation | Browser sessions, service JWTs, CORS, CSRF, and headers stay in their intended boundary. |
| `edge-spring-boot-starter` | Spring Boot auto-configuration | A WebFlux edge app can import the reference perimeter chains and properties through a starter. |
| `edge-testkit` | Edge policy contracts | Consumers can reuse property and perimeter policy checks around CORS, headers, and credential-plane defaults. |
| `supply-chain` | Build trust horizon | SBOM evidence, base-image pinning, wrapper pinning, and workflow-action pinning are executable checks, not review-only guidance. |
| `supply-chain-testkit` | Supply-chain contracts | Build-policy implementers can reuse SBOM, base-image-pin, and action-pin contract tests. |
| `crypto` | Provider seam and algorithm registry | Signing call sites stay stable while algorithms and providers change behind the seam, and verification can be anchored to deployment-trusted keys. |
| `crypto-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can inject `DocumentSigner`; default signing requires app-owned key custody or explicit local-demo opt-in. |
| `crypto-testkit` | Provider and signer contracts | Provider implementers can reuse contract tests instead of copying internal test code. |

## Production Adoption

Bulwark is designed for real production apps, but adoption must be explicit.
The modules provide tested boundaries and implementation patterns; your app owns
its environment-specific issuer, keys, database roles, tenant source of truth,
policy store, observability, incident process, and compliance validation.

Typical adoption paths:

- **Library adoption:** publish modules with `./gradlew publishToMavenLocal` or
  your internal Maven repository, then depend on selected modules.
- **Source adoption:** copy a module into a service and preserve the tests as
  contract tests while adapting package names and infrastructure.
- **Pattern adoption:** use the ADRs and tests as acceptance criteria for an
  existing platform implementation.

See [Production adoption guide](docs/PRODUCTION_ADOPTION.md) for integration
contracts, replacement points, and module-by-module hardening notes.

## Repository Layout

```text
bulwark/
|-- shared/                  # typed cross-module identifiers
|-- shared-testkit/          # reusable typed identifier contracts
|-- tenant-isolation/        # tenant placement, session binding, PostgreSQL RLS
|-- tenant-isolation-spring-boot-starter/ # optional Boot auto-configuration
|-- tenant-isolation-testkit/ # reusable tenant context contracts
|-- authorization/           # coarse request gate + fine-grained policy
|-- authorization-spring-boot-starter/ # optional Boot auto-configuration
|-- authorization-testkit/   # reusable authorization contracts
|-- authorization-showcase/  # demonstration web app: route gate + document API (not published)
|-- edge/                    # BFF edge: dual credential planes, headers, CORS, CSRF
|-- edge-spring-boot-starter/ # optional Boot auto-configuration
|-- edge-testkit/            # reusable edge policy contracts
|-- supply-chain/            # build trust horizon: SBOM, dependency scan, base-image pin
|-- supply-chain-testkit/    # reusable supply-chain contracts
|-- crypto/                  # stable API, JCA providers, signer, registry
|-- crypto-spring-boot-starter/ # optional Boot auto-configuration
|-- crypto-testkit/          # reusable contract tests and fakes
|-- examples/                # standalone consumer examples
|-- docs/
|   |-- adr/                 # architecture decision records
|   `-- GLOSSARY.md          # shared vocabulary
|-- gradle/                  # version catalog and wrapper files
|-- CONVENTIONS.md           # repository rules
`-- README.md
```

## Architecture Posture

The repository demonstrates a layered posture where controls are structural,
explicit, and deny-by-default.

| Layer | Concern | Module |
|---|---|---|
| 1. Identity / AuthN | OIDC, PKCE, browser/service credential separation | `edge` |
| 2. Authorization | Coarse route gate plus fine-grained resource policy | `authorization` (route gate demonstrated in `authorization-showcase`) |
| 3. Secrets / config | No production secret in source or image | ADR-0001 and release checklist |
| 4. Transport / runtime | Perimeter routing, browser headers, actuator lockdown | `edge` |
| 5. Data | Tenant placement, least-privilege roles, RLS | `tenant-isolation` |
| 6. Supply chain | SBOM, dependency, wrapper, base-image, and workflow-action verification | `supply-chain` |
| Cross-cutting | Signature-provider agility and migration strategy | `crypto` |

The posture is executable, not just a diagram:
[`examples/five-layer-spring-boot`](examples/five-layer-spring-boot/) composes a BFF (edge
perimeter, layers 1 + 4) in front of a resource service (authorization + tenant-isolation,
layers 2 + 5) and proves with integration tests that a single request crosses the coarse route
gate, the fine-grained audited decision, and PostgreSQL row-level security -- each with its own
observable refusal.

## Public Release Posture

- This repository is intentionally neutral and uses fictional identifiers such as
  `acme` and `globex`.
- Do not add real customer, tenant, employer, internal-system, endpoint, or secret
  values to examples, tests, docs, issues, or pull requests.
- Cryptographic examples demonstrate API shape and migration boundaries. Local
  ephemeral signing keys are demo-only, and a listed algorithm or FIPS-approved
  algorithm identity is not a claim that every runtime provider, deployment, or
  environment is FIPS-validated.
- Production systems still need their own threat model, operational controls,
  compliance review, provider validation, and incident process.

## Documentation

- [Conventions](CONVENTIONS.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Changelog](CHANGELOG.md)
- [Production adoption guide](docs/PRODUCTION_ADOPTION.md)
- [Glossary](docs/GLOSSARY.md)
- [Architecture decisions](docs/adr/README.md)

## Development

Useful commands:

```bash
./gradlew test
./gradlew build
./gradlew :tenant-isolation:test --tests "*SchemaIsolationModeIntegrationTest"
./gradlew :authorization-showcase:test --tests "*DocumentControllerSecurityTest"
./gradlew :edge:test --tests "*RouteAuthorizationTest"
./gradlew :supply-chain:test --tests "*SbomIntegrityTest"
./gradlew :crypto:test
```

Repository rules:

- One module demonstrates one pattern.
- A module must build from a clean clone with only JDK 21 and Docker.
- Shared types live in `shared` once, never duplicated.
- ADRs are append-only decision records.
- Examples use neutral fictional values such as `acme` and `globex`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
