# Changelog

All notable changes to this project will be documented in this file.

This project follows the spirit of Keep a Changelog and uses semantic versioning
once public version tags begin.

## [Unreleased]

### Added

- `examples/tenant-isolation-spring-boot` — the tenant-isolation implementation
  walkthrough as a compiled, tested consumer application: one starter
  dependency, environment-bound configuration, the single `TenantBindingFilter`
  an adopter owns, and an adopter-adapted copy of the reference DDL around a
  zero-predicate `/notes` API. Its integration test drives two tenants and two
  organizations through real HTTP into RLS-enforced PostgreSQL 18, and the
  testkit contract runs as a consumer would run it. Building the example
  surfaced a walkthrough gap, now fixed in the module README: adopter
  configuration must disable Hibernate's boot-time metadata connection
  (`spring.jpa.properties.hibernate.boot.allow_jdbc_metadata_access: false`)
  because that borrow happens before any tenant is bound and fails closed. The
  walkthrough's inline filter listing moved into the example as compiled code.
- `TrustAnchor` in crypto-agility and a trust-anchored
  `DocumentSigner.verify(document, trustAnchor)` overload: the embedded-key
  verify proves payload integrity only, so a key-substitution forgery (tampered
  payload re-signed under an attacker-chosen key) verified. The anchor holds
  the deployment's own opinion of which public key may speak for a key id —
  `TrustAnchor.pinnedKeys(...)` is the constant-time pinned-set implementation —
  and the anchored verify fails closed on an untrusted key (audited as
  `untrusted key`) before any signature computation.
- `ActionPinPolicy` in supply-chain — the third pin policy, completing the
  triad with `BaseImagePolicy` and `WrapperPinPolicy`: every external GitHub
  Actions `uses:` reference must name an immutable revision (40-hex commit SHA;
  `docker://` refs digest-pinned; repository-local composite actions exempt).
  Asserted continuously against this repository's own workflows — the CI SHA
  pins were previously a hand-maintained convention — and exported as
  `ActionPinPolicyContract` for adopters.
- `PolicyScopeType.TEAM` and `shared`'s `TeamId`: a team is the narrowest
  role-assignment scope — a discretionary grant boundary inside one
  organization, never a data-plane isolation dimension. A team-scoped
  assignment carries both its organization and its team and matches only a
  resource placed in the same organization *and* team, so a grant cannot escape
  its organization even if a team identifier were reused. New `TEAM_MEMBER`
  grant basis reports team as the most specific allowing scope;
  `ProtectedResource` gains an optional team placement (existing constructors
  unchanged).
- `Action.CREATE` in the layered-authorization policy vocabulary: creation is
  decided against the prospective resource's placement, holds the same
  per-action granularity (a `CREATE` grant inherits nothing from `UPDATE` and
  vice versa), and is appended after `DELETE` so persisted ordinals stay
  stable.
- Entitlement-based cross-tenant read grants (ADR-0008): an explicit,
  platform-administered grant ledger (`tenant_security.read_grant`) and a
  `PERMISSIVE FOR SELECT` policy let one tenant read another tenant's rows of
  one resource class — directional, expiring, revocable on the next statement,
  structurally read-only, and unforgeable/unenumerable from inside a tenant
  session. The RESTRICTIVE organization cap now scopes only the session's own
  tenant, so organization-bound sessions keep their entitled foreign reads.
- Tenant-isolation README implementation walkthrough: an end-to-end adoption
  guide for tenancy plus organizations — dependencies, configuration, the one
  request-binding filter an adopter owns, the database-side DDL contract, and
  the layered-authorization tie-in.
- Organization scope within tenant isolation (ADR-0007): the organization is a
  co-equal dimension of the tenant binding (`TenantContext.runAs(tenant,
  organization, work)`), emitted as a second kind-separated signed claim
  (`app.org_claim`, `v2o`) on every borrow, verified by
  `tenant_security.current_org_id()`, and capped by a RESTRICTIVE row policy
  AND-combined with the tenant policy. Posture is selected with
  `tenant.binding.organization-scope` (`off` default, `optional`, `required`
  with fail-closed borrows), so multi-tenancy with organizations is
  database-enforced, not a query-predicate convention.
- Spring Boot configuration metadata across the toolkit: IDE completion and
  documentation for every module property (`edge.*`, `tenant.isolation.*`,
  `tenant.binding.*`, `bulwark.crypto.*`), every starter gate flag
  (`bulwark.*.enabled`), and `showcase.demo-identity`, including default values.
- `shared`: `RequiredText`, the single required-text rule set (non-blank, no
  edge whitespace, no control characters) now used by tenant-isolation and the
  crypto-agility starter instead of per-module copies.
- Public release documentation: security policy, contribution guide, changelog,
  and public release checklist.
- Production adoption guide and stronger public positioning as a Java 21
  security toolkit for multi-tenant SaaS applications.
- Maven publication metadata for local/internal artifact consumption.
- CI hardening for build/test verification and pull-request dependency review.
- Crypto-agility now publishes optional `crypto-agility-spring-boot-starter`
  and `crypto-agility-testkit` artifacts alongside the core `crypto-agility`
  library.
- Shared, tenant isolation, layered authorization, edge perimeter, and supply
  chain now publish reusable testkit artifacts for adopters and implementers.
- Tenant isolation, layered authorization, and edge perimeter now publish
  optional Spring Boot starter artifacts.
- Initial public-ready reference modules: `shared`, `tenant-isolation`,
  `layered-authorization`, `edge-perimeter`, `supply-chain`, and `crypto-agility`.
- ADR-backed documentation for the layered security posture.
- Test coverage for tenant isolation, authorization, perimeter controls,
  supply-chain checks, and crypto-agility seams.

### Changed

- The edge-perimeter CORS registrations are derived from the same
  `RouteAuthorities` constants the authorization rules use, so the browser-plane
  route truth lives once and the CORS surface cannot drift from the routes.
  (`SignatureAlgorithm.fromJoseAlg` also moved from a per-call scan to a
  precomputed map — it sits on the verification hot path.)
- `CryptoAgilityProperties` is now an immutable `@ConfigurationProperties`
  record binding only the values the wiring consumes (`default-algorithm`,
  `default-key-id`). The provider and ephemeral-key toggles remain
  `@ConditionalOnProperty`-driven and are documented in configuration metadata.
  A malformed `bulwark.crypto.default-key-id` is rejected at bind time with
  `IllegalArgumentException` (previously `IllegalStateException` at bean
  creation).
- The edge-perimeter Spring Boot starter now activates each credential plane only
  when its OAuth2 infrastructure is configured — the browser OIDC login chain when
  a client registration is present, the service resource-server chain when a JWT
  decoder is present. A reactive application can adopt the starter without OAuth2
  configured and receives the credential-plane-agnostic hardening (CORS, CSRF,
  cookie policy, credential isolation) instead of a context-startup failure.
- Document ownership persists the owner principal type alongside the key, so the
  policy's cross-principal-type ownership check holds for database-backed
  resources (added an `owner_principal_type` column and a both-or-neither check).

### Removed

- `DocumentSigner.seal(...)`, the alias of `sign(...)` — one entry point per
  operation. ADR-0006 carries the amendment note.

### Fixed

- The OWASP dependency-check gate is applied at the build root and run in CI
  (weekly schedule and on demand) via `dependencyCheckAggregate`, scanning every
  module's runtime closure (Spring Boot, WebFlux, Netty, Tomcat, PostgreSQL)
  rather than only `supply-chain`'s direct dependencies.

### Security

- Typed identifiers (`TenantId`, `OrganizationId`, `ResourceId`) reject the
  reserved nil UUID, so a sentinel/zeroed value cannot flow as an identity.
- Gradle build-tool integrity: CI validates the committed `gradle-wrapper.jar`
  against Gradle's published checksums (`validate-wrappers`), and `WrapperPinPolicy`
  asserts the distribution SHA-256 pin as an executable check.
- All GitHub Actions in CI are pinned to immutable commit SHAs instead of mutable
  major tags.
- The exported `AuthorizationPolicyContract` now also asserts deny-by-default and
  organization-scope isolation, so an adopter's policy is verified against those
  boundaries, not only tenant mismatch and explicit deny.
- The exported `AuthorizationPolicyContract` additionally asserts team-scope
  isolation: a team-scoped grant reaches neither another team's resources nor
  team-unplaced resources of the same organization.
