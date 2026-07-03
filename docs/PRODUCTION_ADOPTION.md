# Production Adoption Guide

This toolkit works in production applications. It is not only sample code. Each module has a narrow boundary. Each module ships executable tests. Docs explain the reasoning behind it.

Production adoption still requires integration work. The modules cannot know these. Your identity provider. Your tenant source of truth. Your deployment topology. Your key custody. Your monitoring stack. Your incident process. Your compliance obligations.

## Adoption Modes

### Internal Maven Artifacts

Publish the modules to Maven. Use a local or internal repository:

```bash
./gradlew publishToMavenLocal
```

Then consume selected modules:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:shared:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:tenant-isolation:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:authorization:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:edge:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:supply-chain:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:crypto:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:shared-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:tenant-isolation-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:authorization-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:edge-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:supply-chain-testkit:0.1.0-SNAPSHOT")
    testImplementation("io.github.joshuamatosdev.security:crypto-testkit:0.1.0-SNAPSHOT")
}
```

Spring Boot applications can instead add:

```kotlin
dependencies {
    implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:authorization-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:edge-spring-boot-starter:0.1.0-SNAPSHOT")
    implementation("io.github.joshuamatosdev.security:crypto-spring-boot-starter:0.1.0-SNAPSHOT")
}
```

The Spring Boot starters are optional. Use them when reference config fits. It should match your service shape. Otherwise, use the core module directly. Or copy the source module. Keep the testkit contracts intact.

### Source Modules

Copy a module into your service. Keep its tests running. This works best for:

- tenant placement and PostgreSQL RLS wiring
- authorization policy and audit decisions
- BFF security-chain structure
- supply-chain checks and build policy

Are you adapting source? Keep the package boundaries clear. Update the ADR that records it.

### Acceptance-Criteria Adoption

Use the tests and ADRs. Treat them as acceptance criteria. Apply them to an existing platform. This path often fits. Your app may have a gateway. Or an authorization service. Or a database topology.

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

Production-ready as a small typed-identifier kernel. Keep this module stable. Why? Downstream modules depend on it. It prevents identity confusion. That covers tenant, organization, and resource. `shared-testkit` carries reusable contracts. They cover identifier factories. Also value equality. Also string round-trips.

### `crypto`, `crypto-spring-boot-starter`, and `crypto-testkit`

Good candidates for library adoption. Stable contracts live in `io.github.joshuamatosdev.security.crypto.api`. Local JCA code lives outside it. That code is replaceable. Spring apps can use the starter. It auto-wires `DocumentSigner`. Provider authors reuse the testkit contracts. Before production use:

- Bind key handles to key custody.
- Configure the default provider explicitly. Set the key id too.
- Keep `bulwark.crypto.local-ephemeral-keys.enabled=false` outside local demos.
- Validate provider behavior in your runtime.
- Separate algorithm identity from validation. That means FIPS or compliance.
- Add artifact signing and key-rotation runbooks.

### `tenant-isolation`

Adopt it three ways. As a library. As a source module. As an integration pattern. Spring apps can start with `tenant-isolation-spring-boot-starter`. Provider-specific tenant-context code reuses `tenant-isolation-testkit`. Before production use:

- Provision non-superuser runtime roles. Provision system-ops roles too. Do this outside application code.
- Inject tenant claim secrets. Use a secret manager.
- Verify RLS policies carefully. Use the exact production PostgreSQL version.
- Prove transaction ordering under your stack. Prove tenant context binding too.
- Add operational alerts. Watch pool identity. Watch RLS verification failures.

### `authorization`

Adopt three things. The decision model. The audit contract. The deny-overrides behavior. Spring apps can start with `authorization-spring-boot-starter`. Policy implementers can reuse `authorization-testkit`. Before production use:

- Replace demo role resolution. `authorization-showcase` illustrates it. Use a real authorization store.
- Model revocation and authorization-version behavior.
- Send audit records to durable storage.
- Decide how policy changes flow. Review them. Stage them. Roll them back.

### `edge`

Adopt the security-chain shape and tests. Spring WebFlux edge apps use `edge-spring-boot-starter`. Perimeter policy adopters can reuse `edge-testkit`. Before production use:

- Register real OAuth2/OIDC clients.
- Pin issuer and audience values.
- Configure real CORS origins.
- Verify cookie, CSRF, and header behavior. Test it behind your TLS terminator.
- Add outbound routing carefully. Add token relay carefully. First preserve browser/service plane separation.

### `supply-chain` and `supply-chain-testkit`

Adopt `supply-chain` directly into CI. Building similar checks in another build? Use `supply-chain-testkit` instead. It covers SBOM policy checks. Also base-image-pin policy checks. Before production use:

- Enable dependency review. Enable secret scanning. Do this in the host repository.
- Publish SBOMs with release artifacts.
- Pin base images by digest.
- Decide when dependency-check runs. On every PR? Nightly? Release only?
- Add artifact signing and provenance. Do it if the release requires.

## Release Expectations

Production consumers, note this. Treat public tags as compatibility points:

- Patch releases fix bugs. They keep module contracts intact.
- Minor releases may add APIs. Or new modules.
- Major releases may change package contracts. Or policy semantics.

The APIs are still pre-stable. That holds until `1.0.0`. Still treat them as production-oriented. Pin exact versions. Read the changelog before upgrading.

## Non-Negotiable Production Checks

Before using derived code in production:

```bash
./gradlew build publishToMavenLocal
gitleaks detect --source . --redact --verbose
```

Also run the module tests. Use your chosen database. Your identity provider. Your runtime provider. Your deployment topology. The project does not skip work. It gives you strong security contracts. Those contracts are executable. You start from them.
