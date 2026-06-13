# Bulwark

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
./gradlew :layered-authorization:test
./gradlew :layered-authorization-spring-boot-starter:test
./gradlew :layered-authorization-testkit:test
./gradlew :edge-perimeter:test
./gradlew :edge-perimeter-spring-boot-starter:test
./gradlew :edge-perimeter-testkit:test
./gradlew :supply-chain:test
./gradlew :supply-chain-testkit:test
./gradlew :crypto-agility:test
./gradlew :crypto-agility-spring-boot-starter:test
./gradlew :crypto-agility-testkit:test
./gradlew :shared:test
./gradlew :shared-testkit:test
```

The test suite starts PostgreSQL containers where a pattern depends on real
database behavior.

## What You Can Use

```mermaid
flowchart LR
    Browser["Browser / SPA"] --> Edge["edge-perimeter<br/>OIDC, PKCE, CORS, CSRF, headers"]
    Service["Service client"] --> Edge
    Edge --> Authz["layered-authorization<br/>route gate + resource policy + audit"]
    Authz --> Tenant["tenant-isolation<br/>placement + signed session claim + RLS"]
    Tenant --> Postgres[("PostgreSQL")]
    Shared["shared<br/>typed identifiers"] --> Authz
    Shared --> Tenant
    Crypto["crypto-agility<br/>provider seam + algorithm registry"] -. signs/verifies .-> Authz
    Supply["supply-chain<br/>SBOM + dependency/base-image checks"] -. verifies .-> Build["Build"]
```

| Module | Security pattern | What the tests prove |
|---|---|---|
| `shared` | Typed identity kernel | Tenant, organization, and resource IDs cannot be casually mixed as raw UUIDs. |
| `shared-testkit` | Typed identifier contracts | Adopters can reuse constructor, equality, and formatting contracts for shared identifier implementations. |
| `tenant-isolation` | Tenant placement, signed PostgreSQL session claims, and RLS | Tenant context reaches the database boundary and isolation holds under real PostgreSQL behavior. |
| `tenant-isolation-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can import the tenant isolation configuration through one starter dependency. |
| `tenant-isolation-testkit` | Tenant context contracts | Adopters can prove context binding, clearing, and cross-tenant rejection without copying reference tests. |
| `layered-authorization` | Coarse route gate plus fine-grained resource policy | Route, resource, deny-overrides, and audit behavior are enforced from the same decision point. |
| `layered-authorization-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can auto-wire the reference authorization service and policies. |
| `layered-authorization-testkit` | Authorization policy contracts | Policy implementers can reuse allow, deny, mismatch, and audit-oriented contract checks. |
| `edge-perimeter` | Browser/service credential plane separation | Browser sessions, service JWTs, CORS, CSRF, and headers stay in their intended boundary. |
| `edge-perimeter-spring-boot-starter` | Spring Boot auto-configuration | A WebFlux edge app can import the reference perimeter chains and properties through a starter. |
| `edge-perimeter-testkit` | Edge policy contracts | Consumers can reuse property and perimeter policy checks around CORS, headers, and credential-plane defaults. |
| `supply-chain` | Build trust horizon | SBOM evidence and base-image pinning are executable checks, not review-only guidance. |
| `supply-chain-testkit` | Supply-chain contracts | Build-policy implementers can reuse SBOM and base-image-pin contract tests. |
| `crypto-agility` | Provider seam and algorithm registry | Signing call sites stay stable while algorithms and providers can change behind the seam. |
| `crypto-agility-spring-boot-starter` | Spring Boot auto-configuration | A Spring app can inject `DocumentSigner`; default signing requires app-owned key custody or explicit local-demo opt-in. |
| `crypto-agility-testkit` | Provider and signer contracts | Provider implementers can reuse contract tests instead of copying internal test code. |

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
|-- layered-authorization/   # coarse request gate + fine-grained policy
|-- layered-authorization-spring-boot-starter/ # optional Boot auto-configuration
|-- layered-authorization-testkit/ # reusable authorization contracts
|-- edge-perimeter/          # BFF edge: dual credential planes, headers, CORS, CSRF
|-- edge-perimeter-spring-boot-starter/ # optional Boot auto-configuration
|-- edge-perimeter-testkit/  # reusable edge policy contracts
|-- supply-chain/            # build trust horizon: SBOM, dependency scan, base-image pin
|-- supply-chain-testkit/    # reusable supply-chain contracts
|-- crypto-agility/          # stable API, JCA providers, signer, registry
|-- crypto-agility-spring-boot-starter/ # optional Boot auto-configuration
|-- crypto-agility-testkit/  # reusable contract tests and fakes
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
| 1. Identity / AuthN | OIDC, PKCE, browser/service credential separation | `edge-perimeter` |
| 2. Authorization | Coarse route gate plus fine-grained resource policy | `layered-authorization` |
| 3. Secrets / config | No production secret in source or image | ADR-0001 and release checklist |
| 4. Transport / runtime | Perimeter routing, browser headers, actuator lockdown | `edge-perimeter` |
| 5. Data | Tenant placement, least-privilege roles, RLS | `tenant-isolation` |
| 6. Supply chain | SBOM, dependency, wrapper, and base-image verification | `supply-chain` |
| Cross-cutting | Signature-provider agility and migration strategy | `crypto-agility` |

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
./gradlew :layered-authorization:test --tests "*DocumentControllerSecurityTest"
./gradlew :edge-perimeter:test --tests "*RouteAuthorizationTest"
./gradlew :supply-chain:test --tests "*SbomIntegrityTest"
./gradlew :crypto-agility:test
```

Repository rules:

- One module demonstrates one pattern.
- A module must build from a clean clone with only JDK 21 and Docker.
- Shared types live in `shared` once, never duplicated.
- ADRs are append-only decision records.
- Examples use neutral fictional values such as `acme` and `globex`.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
