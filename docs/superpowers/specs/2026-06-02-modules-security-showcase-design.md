# Design — `modules`: a buildable security-architecture reference repo

- **Date:** 2026-06-02
- **Author:** Joshua Matos (`joshuamatosdev`)
- **Status:** Approved (pending spec review)
- **Package namespace:** `io.github.joshuamatosdev.security`

## Purpose

A **public**, self-contained, buildable reference repository that demonstrates a
production-grade platform security methodology — multi-tenant data isolation,
layered authorization, an edge perimeter, cryptographic agility, and signed
supply chain — as a portfolio artifact. Each pattern is a real, runnable,
tested module, not a code dump.

The patterns are **drawn from production experience** building a multi-tenant
credentialing platform. The repo does **not** name, brand, or expose that
product. It is attributed to the author as a personal security-architecture
reference.

### Success criteria

1. Each module builds and its tests pass from a clean clone (`./gradlew :<module>:test`).
2. Each module is independently liftable (its own build file + README + ADR).
3. Zero real production identifiers (see Sanitization rules).
4. A reader can trace the **five-layer security posture** from the root README
   into each module as a concrete proof of one layer.

## Non-goals (YAGNI)

- Not a framework or a library to depend on — a reference, not a product.
- No Part-B key-custody or credential-signing modules (explicitly de-scoped by owner).
- No real production code copied verbatim; no live-system internals.
- No public remote created or pushed until the owner explicitly authorizes it.

## Approach

One **Gradle multi-module monorepo**. `docs/adr/` is the methodology backbone;
each pattern is an independently-buildable module with its own `build.gradle(.kts)`,
`README.md`, ADR, and tests. Mirrors the modular + portable convention of the
source workspace: one GitHub link, many liftable parts.

Rejected alternatives:
- *Separate repo per pattern* — max portability, but fragments the portfolio.
- *Single app with packages* — simplest build, but not modular/portable.

### Stack

- **Java 21 + Gradle**, matching the author's production stack (credibility).
- **Spring Boot + Spring Security** where a running app/gateway is required
  (the platform modules).
- **Plain Java (zero framework)** for `crypto-agility` and `supply-chain`, so
  those are maximally portable.
- **Testcontainers (Postgres)** for the `tenant-isolation` integration tests.

## Architecture — spine = the five-layer security posture

Root README and `docs/adr/` tell the five-layer story; each module is a runnable
proof of one layer:

| Layer | Posture concern | Proving module |
|---|---|---|
| 1 — Identity / AuthN | OIDC + PKCE, MFA / step-up | `edge-perimeter` (resource-server + PKCE relay) |
| 2 — Authorization | coarse edge + fine-grained service, deny-by-default | `layered-authorization` |
| 4 — Transport / runtime | perimeter, headers, actuator lockdown | `edge-perimeter` |
| 5 — Data | per-service DB roles, RLS, least privilege | `tenant-isolation` |
| 5 — Supply chain | SBOM, signing, dep-scan, base-image pin | `supply-chain` |
| (cross-cutting) | crypto strategy, agility, PQC roadmap | `crypto-agility` |

## Modules (all buildable + tested)

### Platform A (full)

**`tenant-isolation`** — *flagship.*
PostgreSQL Row-Level Security + session-bound `app.current_tenant` GUC, with a
**non-superuser pool identity**. Spring Boot + JPA + Testcontainers.
- Test: cross-tenant read returns empty for the bound tenant.
- Test: cross-tenant write is rejected.
- **Audit test** that fails if the application login role is a Postgres
  superuser — encoding the real lesson that `FORCE ROW LEVEL SECURITY` does
  **not** constrain a superuser session, so the pool identity itself must be
  `NOSUPERUSER NOBYPASSRLS`. The module README narrates "bypass found → fixed
  forward-only" as a methodology highlight.

**`layered-authorization`**
- Sealed typed principal (`UserPrincipal` / `ServicePrincipal`).
- Immutable `RequestContext` resolved once per request, passed by parameter.
- Access-variant model: tenant-membership, organization-membership,
  resource-grant (ownership), and an audited wide-scope admin short-circuit.
- A `PolicyService` boundary + method security; deny-by-default.
- Tests for each variant: grant path, deny path, and a deny-log assertion.

**`edge-perimeter`** (backend-for-frontend gateway)
- Coarse `hasRole(...)` route map, deny-by-default (unmatched → 403).
- OAuth2 resource-server; Authorization-Code + PKCE relay.
- CSRF for browser clients, CORS allow-list, security headers, actuator lockdown.
- WebTestClient tests for route authorization + header presence.

### Part B (subset chosen by owner)

**`crypto-agility`** (plain Java)
- Algorithm registry + versioned key handles + provider seam.
- A hybrid classical + post-quantum signature migration path (e.g. classical
  Ed25519/ECDSA alongside an ML-DSA-style PQC algorithm behind the same seam).
- Test: an algorithm swap leaves call sites unchanged (the agility property).
- Carries the crypto-strategy + agility + PQC-roadmap ADRs.

**`supply-chain`** (plain Java + build/CI config)
- CycloneDX SBOM generated on build.
- A verification/attestation gate; dependency scan; base-image-pin policy.
- Test: SBOM is produced and a verification step asserts its integrity.

## Decomposition (phased — too big for one plan)

Each module is its own spec → plan → build cycle. The **first deliverable is the
skeleton + `tenant-isolation` end-to-end**, so the repo is immediately
non-hollow and shows the flagship. Then the remaining four modules land one at a
time as clean, reviewed increments.

```
SP0  skeleton            root Gradle build, conventions, docs/adr backbone
                         (sanitized methodology ADRs), root README, CI, LICENSE,
                         module layout. Buildable empty composite.
SP1  tenant-isolation    first crown jewel, incl. the "bypass found & fixed" story
SP2  layered-authorization
SP3  edge-perimeter
SP4  crypto-agility + PQC roadmap
SP5  supply-chain
```

This spec covers the overall repo design **and** scopes SP0 + SP1 as the first
implementation plan. SP2–SP5 each get their own plan when reached.

## Sanitization rules (non-negotiable — public repo)

- Neutral fictional domain. Example tenants `acme` / `globex`; generic roles
  (`platform_admin`, `member`); neutral resource nouns.
- Package namespace `io.github.joshuamatosdev.security.*` — never
  `com.doctrineone.ttx.*`.
- **Zero** real tenant UUIDs, the `patriot` realm name, real endpoint paths, or
  any value from the source workspace's `.env` / credentials inventory.
- ADRs are re-authored sanitized narratives — decision + rationale + tradeoffs —
  not copies of the source ADRs.
- `git init` is local only. No public remote is created or pushed until the
  owner explicitly authorizes it.

## Verification

- SP0: `./gradlew build` succeeds on the empty composite; `docs/adr/` renders;
  root README links every planned module.
- SP1: `./gradlew :tenant-isolation:test` passes from a clean clone, including
  the cross-tenant-empty test and the superuser-pool audit test.
- Per module thereafter: `./gradlew :<module>:test` green from a clean clone.
