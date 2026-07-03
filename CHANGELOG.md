# Changelog

All notable changes live here. Versions follow semantic versioning.

Entries mirror the commit history. One section per history segment. Oldest first, so read downward.

## [Unreleased]

### 1. Foundation

- Design basis written before code. Gradle composite skeleton shipped.

### 2. Posture and first ADRs

- Five-layer posture documented. License and conventions added.
- ADR-0001 and ADR-0002 recorded.

### 3. Tenant isolation, v1

- RLS under non-superuser pool. Session binding shipped.

### 4. Authorization and shared kernel

- Decision module added. Typed identifier kernel added.

### 5. Tenant isolation hardening

- Claims are HMAC-signed. PostgreSQL verifies before trusting.
- Binding fails closed everywhere. Database owns UUIDv7 keys.

### 6. Edge, supply-chain, crypto

- Dual-plane BFF edge added. Issuer and audience validated.
- Supply-chain trust checks added. Crypto provider seam added.

### 7. Cross-module hardening

- Verify fails closed. Cookies are Secure by default.
- Claim TTL is 120 seconds. CSP headers tightened.

### 8. Starters and testkits

- Every module ships a starter. Every module ships a testkit.

### 9. Publication shape

- Boot modules publish library jars. API dependencies are compile-scoped.
- First consumer examples build.

### 10. Supply-chain scanning and JDBC hardening

- CVE scanning wired with NVD. pgJDBC URL downgrades blocked.
- Vulnerable dependencies upgraded.

### 11. Release readiness

- Eleven audit findings fixed. Shims collapsed into modules.
- System-writer tier added. Public metadata prepared.

### 12. Metadata and RequiredText

- All properties have IDE metadata. `RequiredText` becomes the text rule.

### 13. Organization scope and grants

- Organizations scope the tenant binding. The database enforces both claims.
- Explicit grants allow cross-tenant reads. Grants expire and stay read-only.

### 14. Policy growth

- Teams are the narrowest scope. `Action.CREATE` joins the policy.
- `ActionPinPolicy` requires SHA-pinned actions. `TrustAnchor` adds authenticity checks.
- CORS derives from route constants.

### 15. Tenant walkthrough example

- Walkthrough became a tested app. CI builds every example.

### 16. Plain module names

- Modules renamed to plain names. Nothing published, nothing breaks.

### 17. Adversarial review fixes

- Twenty-two confirmed findings fixed. Every module was touched.
- `authorization` stays framework-free. Demo web app split out.
- Wrong keys fail closed. Every verify failure gets audited.
- Starter back-off is per bean. URI predicates live once.

### 18. Five-layer composed example

- Two apps compose five layers. Tests prove each layer's refusal.
- A real starter bug found. Auto-configuration ordering fixed.

### 19. Release engineering

- Runtime closures are build-checked. One report merges all coverage.
- Dependabot updates all build roots. Tags build and create releases.
- Pushes publish Javadoc to Pages. Artifact signing is env-gated.

### 20. Gate coverage invariant

- Every endpoint must match rules. Unmatched endpoints fail the build.

### 21. Plain repository identity

- The repository is `java-security-toolkit`. The brand name is gone.
- Config prefixes match module roots. `authorization.enabled`, `edge.enabled`, `crypto.*`, `tenant.isolation.enabled`.
- Nothing was published. Nothing breaks.
