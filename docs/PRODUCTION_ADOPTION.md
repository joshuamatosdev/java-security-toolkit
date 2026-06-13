# Production Adoption Guide

Bulwark is designed to be useful in production applications. It is not
only sample code: each module has a narrow security boundary, executable tests,
and documentation that explains the reasoning behind the boundary.

Production adoption still requires integration work. The modules cannot know
your identity provider, tenant source of truth, deployment topology, key custody,
monitoring stack, incident process, or compliance obligations.

## Adoption Modes

### Internal Maven Artifacts

Publish the modules to a local or internal Maven repository:

```bash
./gradlew publishToMavenLocal
```

Then consume selected modules:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:shared:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:tenant-isolation:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:layered-authorization:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:edge-perimeter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:supply-chain:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:crypto-agility:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:shared-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:tenant-isolation-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:layered-authorization-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:edge-perimeter-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:supply-chain-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:crypto-agility-testkit:0.1.0-SNAPSHOT")
}
```

Spring Boot applications can instead add:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:layered-authorization-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:edge-perimeter-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:crypto-agility-spring-boot-starter:0.1.0-SNAPSHOT")
}
```

The Spring Boot starters are optional. Use them when the reference Spring
configuration matches your service shape; otherwise depend on the core module
directly or copy the source module while preserving the testkit contracts.

### Source Modules

Copy a module into your service and keep its tests running. This works best for:

- tenant placement and PostgreSQL RLS wiring
- authorization policy and audit decisions
- BFF security-chain structure
- supply-chain checks and build policy

When adapting source, keep the module's package boundaries clear and update the
ADR that records the decision.

### Acceptance-Criteria Adoption

Use the tests and ADRs as acceptance criteria for an existing platform. This is
often the right path when your app already has a gateway, authorization service,
or database topology.

## Production Replacement Points

| Area | Demo value | Production replacement |
|---|---|---|
| Tenant IDs | Fictional `acme` and `globex` tenants | Tenant registry or control-plane source of truth |
| Identity provider | Fictional issuer URLs | Real OIDC issuer, JWKS, audience, client registrations, PKCE settings |
| Demo users | Local in-memory accounts | Enterprise identity provider and authorization store |
| Secrets | Local-only test secrets | Secret manager, rotation policy, and deployment-time injection |
| Database roles | Testcontainers initialization SQL | Managed migration path and least-privilege role provisioning |
| Policy rules | In-memory demo rules | Durable policy store with review and rollout controls |
| Crypto keys | JCA software keys | HSM, KMS, hardware-backed wallet key, or validated provider where required |
| Audit sink | Test or log sink | Immutable audit pipeline with retention and investigation workflows |
| Supply chain | Local SBOM/base-image checks | CI-enforced dependency review, artifact signing, provenance, and release gates |

## Module Adoption Notes

### `shared`

Production-ready as a small typed-identifier kernel. Keep this module stable
because downstream modules use it to prevent tenant, organization, and resource
identity confusion. `shared-testkit` carries reusable contracts for identifier
factories, value equality, and string round-trips.

### `crypto-agility`, `crypto-agility-spring-boot-starter`, and `crypto-agility-testkit`

Good candidates for library adoption. Stable contracts live in
`io.github.joshuamatosdev.security.crypto.api`; local JCA code lives outside
that API package and is replaceable. Spring apps can use the starter for
`DocumentSigner` auto-wiring; provider implementers can use the testkit
contracts. Before production use:

- bind key handles to your key custody system
- configure the default provider and key id explicitly
- keep `bulwark.crypto.local-ephemeral-keys.enabled=false` outside local demos
- validate provider behavior in your runtime environment
- separate algorithm identity from FIPS or compliance validation
- add artifact signing and key-rotation runbooks

### `tenant-isolation`

Adopt as a library, source module, or integration pattern. Spring applications
can start with `tenant-isolation-spring-boot-starter`; provider-specific tenant
context implementations can reuse `tenant-isolation-testkit`. Before production
use:

- provision non-superuser runtime roles and system-ops roles outside application code
- inject tenant claim secrets from a secret manager
- verify RLS policies under the exact production PostgreSQL version
- prove transaction ordering and tenant context binding under your framework stack
- add operational alerts for pool identity and RLS verification failures

### `layered-authorization`

Adopt the decision model, audit contract, and deny-overrides behavior. Spring
applications can start with `layered-authorization-spring-boot-starter`; policy
implementers can reuse `layered-authorization-testkit`. Before production use:

- replace demo role resolution with an authorization store
- model revocation and authorization-version behavior
- send audit records to durable storage
- decide how policy changes are reviewed, staged, and rolled back

### `edge-perimeter`

Adopt the security-chain shape and tests. Spring WebFlux edge applications can
start with `edge-perimeter-spring-boot-starter`; perimeter policy adopters can
reuse `edge-perimeter-testkit`. Before production use:

- register real OAuth2/OIDC clients
- pin issuer and audience values
- configure real CORS origins
- verify cookie, CSRF, and header behavior behind your TLS terminator
- add outbound routing or token relay only after preserving browser/service plane separation

### `supply-chain` and `supply-chain-testkit`

Adopt `supply-chain` directly into CI. Use `supply-chain-testkit`
when implementing equivalent SBOM or base-image-pin policy checks in another
build. Before production use:

- enable dependency review and secret scanning in the host repository
- publish SBOMs with release artifacts
- pin base images by digest
- decide whether dependency-check runs on every PR, nightly, or release only
- add artifact signing and provenance if your release process requires it

## Release Expectations

For production consumers, treat public tags as compatibility points:

- patch releases should fix bugs without breaking module contracts
- minor releases may add APIs or modules
- major releases may change package contracts or policy semantics

Until `1.0.0`, the APIs should be considered production-oriented but still
pre-stable. Pin exact versions and read the changelog before upgrading.

## Non-Negotiable Production Checks

Before using Bulwark-derived code in production:

```bash
./gradlew build publishToMavenLocal
gitleaks detect --source . --redact --verbose
```

Also run the module tests against your chosen database, identity provider,
runtime provider, and deployment topology. The point of the project is not to
skip that work; it is to give you strong, executable security contracts to start
from.
