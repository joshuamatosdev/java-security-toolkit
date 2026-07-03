# Changelog

All notable changes live here. Versions follow semantic versioning.

## [Unreleased]

### Added

- Gate coverage test added. Unmatched endpoints fail the build.
- Artifact signing is env-gated. Local builds never need keys.
- Tags build and create releases. Pushes publish Javadoc to Pages.
- Dependabot updates all build roots. Updates arrive weekly, grouped.
- One report merges all coverage. CI posts totals and artifact.
- `assertFrameworkFreeRuntimeClasspath` guards runtime dependencies. Unlisted groups fail the build.
- Two apps compose five layers. Tests prove each layer's refusal.
- Demo web app split out. `authorization` stays framework-free.
- Starter ships the 403 advice. It registers in servlet apps.
- `edge-testkit` adds `CorsAllowListContract`. Adopters prove CORS guards hold.
- Contract covers trust-anchored verify. Wrong keys fail closed.
- Identifier contracts cover more cases. Bad and null text rejected.
- `crypto` now has a README.
- Walkthrough became a tested app. Tests drive real RLS PostgreSQL.
- `TrustAnchor` adds authenticity checks. Substituted keys fail closed.
- `ActionPinPolicy` requires SHA-pinned actions. It checks our own workflows.
- Teams are the narrowest scope. Grants never escape their organization.
- `Action.CREATE` joins the policy. Creation checks prospective placement.
- Explicit grants allow cross-tenant reads. Grants expire and stay read-only.
- README gains an adoption walkthrough.
- Organizations scope the tenant binding. The database enforces both claims.
- All properties have IDE metadata.
- `RequiredText` replaces per-module text rules. Every module uses it.
- Security policy and guides added.
- Production adoption guide added.
- Maven publication metadata added.
- CI verifies builds and dependencies.
- `crypto` publishes starter and testkit.
- All modules publish testkits.
- Three modules publish starters.
- Six reference modules shipped.
- ADRs document the posture.
- Tests cover every module.

### Changed

- Modules renamed to plain names. Nothing published, nothing breaks.
- CORS derives from route constants. Routes and CORS cannot drift.
- `CryptoProperties` is an immutable record. Bad key ids fail binding.
- Credential planes activate when configured. Bare adoption still boots hardened.
- Ownership stores the principal type. Cross-type checks hold in database.

### Removed

- `DocumentSigner.seal(...)` removed. One entry point per operation.

### Fixed

- `TenantPoolSnapshot` accepts weak counts. Observability cannot fault the datasource.
- Restore failures no longer mask. Work errors stay root cause.
- Every verify failure gets audited. `sign` validates key ids first.
- Service replacement keeps reference wiring. Back-off is now per bean.
- URI predicates now live once. Guards cannot drift apart.
- Thread-context docs match the code.
- CVE scanning covers every module. CI runs it weekly.

### Security

- Typed identifiers reject nil UUIDs.
- CI validates the Gradle wrapper. `WrapperPinPolicy` checks the pin.
- All actions pin commit SHAs.
- `AuthorizationPolicyContract` asserts deny-by-default. It asserts organization isolation.
- The contract asserts team isolation.
