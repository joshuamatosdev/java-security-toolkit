# Changelog

All notable changes to this project will be documented in this file.

This project follows the spirit of Keep a Changelog and uses semantic versioning
once public version tags begin.

## [Unreleased]

### Added

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
