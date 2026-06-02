# Skeleton + Tenant Isolation — Implementation Plan (copy-and-refactor)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `modules` reference repo (buildable Gradle composite + methodology backbone) and deliver the flagship `tenant-isolation` module by **copying the real production security cluster and refactoring it in place** into a sanitized, self-contained, buildable form proven by Testcontainers integration tests.

**Strategy (owner directive 2026-06-02):** Copy the relevant code/structures from the production platform, then refactor in place — generalize the domain, strip every production identifier, make it self-contained and buildable. This is **not** write-from-scratch; the value is that the real engineering (and its real lesson) is preserved, just sanitized.

**Architecture:** Gradle multi-module monorepo. `docs/adr/` holds re-authored, sanitized methodology ADRs. `tenant-isolation` is a Spring Boot + JPA module carrying the real tenant cluster: a typed `TenantId`, a `TenantContext` (ThreadLocal, fail-closed), well-known `TenantIds` incl. a system-ops tenant, the `TenantSessionDataSourceProxy` (binds `app.current_tenant` + `app.bypass_rls` per connection borrow, transaction-local vs session-scoped, session-reset-on-close, fail-closed), PostgreSQL RLS DDL (`ENABLE`/`FORCE ROW LEVEL SECURITY` + `p_tenant_isolation`), a 4-tier non-superuser role mesh, and the role-attribute audit that makes "the pool must not be a superuser" a build-breaking invariant.

**Tech Stack:** Java 21, Gradle 8.13 (wrapper), Kotlin DSL build files, Spring Boot 3.5.x (data-jpa starter), Flyway (managed by Boot), PostgreSQL 16, Testcontainers 1.20.x, JUnit 5, AssertJ, JSpecify (`org.jspecify:jspecify`). Package namespace `io.github.joshuamatosdev.security`.

---

## CRITICAL: scrub-before-commit (public repo)

Copy into the working tree → refactor/sanitize → commit **once**, clean. **Never** commit a raw copy and scrub later: git history is public and permanent. Every file below is sanitized in the working tree before its first `git add`.

### Source → showcase sanitization inventory

Real sources live under `C:\projects\ttx-workspace\core`. For each, the exact transforms:

| Real source (read-only) | Showcase file | Sanitization transforms |
|---|---|---|
| `backend/platform/shared/.../tenancy/id/TenantId.java` | `tenant/TenantId.java` | package → `io.github.joshuamatosdev.security.tenant`; keep record(UUID) + Jackson annotations + validation verbatim. |
| `backend/platform/shared/.../security/context/SystemTenantBoundary.java` | `tenant/SystemTenantBoundary.java` | package only. |
| `backend/platform/shared/.../persistence/tenant/TenantIds.java` | `tenant/TenantIds.java` | package; **drop `FEDERAL`/`TEXAS_WORKFORCE`** (TTX program identifiers); replace with neutral `ACME`, `GLOBEX` + keep `SYSTEM_OPS`; regenerate fresh UUIDv7-shaped constants (not the real `01960000-…` values). |
| `backend/platform/shared/.../security/context/TenantContext.java` | `tenant/TenantContext.java` | package; keep `runAs`/`supplyAs`/`runAsSystemOps`/fail-closed `requireCurrent` + `TenantBindingScope` verbatim. (Bring `TenantBindingScope` enum too.) |
| `backend/platform/test-support/.../testing/WithTenant.java` | `tenant/testfixtures/WithTenant.java` (test scope) | package; keep verbatim. |
| `backend/platform/shared/.../persistence/tenant/TenantSessionDataSourceProxy.java` | `tenant/TenantSessionDataSourceProxy.java` | package; **replace Micrometer `Metrics.counter(...)` with a dependency-free `TenantBindingObserver` seam** (interface + no-op default + counting impl for tests) — preserves the set/missing/reset-failed observability story without dragging Micrometer into a standalone module; keep ALL security logic verbatim (bind both GUCs, txn-local vs session, fail-closed borrow, session-reset-on-close proxy, `app.principal_*` clears dropped since no principal layer here). |
| `infra/init-db/vectorsearch/00-create-roles.sql` (4-tier mesh) | `src/test/resources/db/init-roles.sql` | **delete the real password literal `ttx-dev-fips-db-password-2026`**; rename `vectorsearch_*` → `tenant_*`; `\c ttx_vectorsearch` → demo DB; keep the app/user/migrator NOLOGIN/LOGIN + NOSUPERUSER NOBYPASSRLS topology faithfully. |
| `infra/init-db/calendar/11-calendar-tables.sql` policy block (L304-318) | `src/main/resources/db/migration/V1__tenant_isolation.sql` | neutralize `calendar.cal_events` → `document`; keep the policy verbatim: `tenant_id` UUID DEFAULT from GUC, `ENABLE`+`FORCE RLS`, `p_tenant_isolation FOR ALL TO public USING (tenant_id = current_setting('app.current_tenant',true)::uuid OR current_setting('app.bypass_rls',true)='on') WITH CHECK (...)`. |
| `backend/.../architecture/tenancy/RoleAttributeSqlAuditTest.java` | `tenant/PoolIdentityAuditTest.java` | strip ADR-0034 §refs, `ttx`/`core/compose.yaml`/`<module>_user` prose; convert from static-yaml audit to a **live runtime audit** (assert `current_user` is `NOSUPERUSER NOBYPASSRLS`) — the cleaner proof for a self-contained demo; ADR notes the production static-yaml technique + why (Testcontainers superuser masks it). |
| `backend/.../architecture/tenancy/RlsCrossTenantQueryTest.java` | `tenant/RlsIsolationTest.java` | neutralize `marketplace.*` domain tables → `document`; keep the proof shape: write under TENANT_A invisible to TENANT_B; author still sees own row; SYSTEM_OPS bypass sees all; cross-tenant write rejected; unbound = fail-closed. |

**Forbidden tokens** (grep gate before every commit — see Task 13): `doctrineone`, `ttx`, `patriot`, `texas`, `federal`, `ttx-dev-fips`, `01960000-`, `marketplace`, `calendar.cal_`, `vectorsearch`.

---

## File Structure

**SP0 — skeleton** (unchanged from prior revision)
- `settings.gradle.kts`, `build.gradle.kts`, `gradle/libs.versions.toml`, `.editorconfig`, wrapper, `LICENSE`, `README.md`, `CONVENTIONS.md`
- `docs/adr/README.md`, `docs/adr/TEMPLATE.md`, `docs/adr/0001-five-layer-security-posture.md`, `docs/adr/0002-tenant-isolation-rls-session-binding.md`
- `.github/workflows/ci.yml`

**SP1 — `tenant-isolation`** (copy-and-refactor; all under `tenant-isolation/`)
- `build.gradle.kts`
- `src/main/resources/application.yaml`
- `src/main/resources/db/migration/V1__tenant_isolation.sql`  ← from calendar policy
- `src/main/java/.../tenant/TenantId.java`, `TenantIds.java`, `SystemTenantBoundary.java`, `TenantBindingScope.java`, `TenantContext.java`  ← copied cluster
- `src/main/java/.../tenant/TenantSessionDataSourceProxy.java`, `TenantBindingObserver.java`  ← copied proxy + de-Micrometer seam
- `src/main/java/.../tenant/DataSourceConfig.java`, `TenantIsolationApplication.java`  ← wiring (new, minimal)
- `src/main/java/.../tenant/DocumentEntity.java`, `DocumentRepository.java`  ← neutral demo aggregate (new, minimal)
- `src/test/resources/db/init-roles.sql`  ← from vectorsearch role mesh
- `src/test/java/.../tenant/testfixtures/WithTenant.java`  ← copied
- `src/test/java/.../tenant/AbstractRlsTest.java`  ← Testcontainers base (new)
- `src/test/java/.../tenant/RlsIsolationTest.java`  ← from RlsCrossTenantQueryTest
- `src/test/java/.../tenant/PoolIdentityAuditTest.java`  ← from RoleAttributeSqlAuditTest
- `README.md`

---

## Phase SP0 — Skeleton

Mechanical scaffolding (wrapper, `.editorconfig`, `LICENSE`, CI yaml, build files) may be delegated to a Sonnet subagent with exact contents. The two ADRs are judgment work (Opus). See the prior plan revision in git history (`594f648`) for the exact, complete contents of: the Gradle wrapper/settings/root build/version catalog (Task 1), LICENSE+README+CONVENTIONS (Task 2), the ADR backbone (Task 3 — ADR-0001 unchanged; **ADR-0002 is superseded by the richer version below**), and CI workflow (Task 4). Apply those verbatim EXCEPT:

- **`gradle/libs.versions.toml`** also adds `jspecify = "1.0.0"` under `[versions]` and a `jspecify` library entry.
- **ADR-0002** uses the expanded body in Task 3' below (adds `bypass_rls`, the 4-tier role mesh, and the static-yaml-vs-runtime audit nuance).

### Task 3' — ADR-0002 (expanded, supersedes prior)

The decision record must now reflect what the real code actually does:
- Policy binds on **both** `app.current_tenant` (UUID) and `app.bypass_rls` (the audited system-ops escape), `FOR ALL TO public`, `USING` == `WITH CHECK`.
- `tenant_id` column **DEFAULTs** from `current_setting('app.current_tenant')` so inserts are stamped by the session, not the caller.
- The runtime pool role is one tier of a **4-tier mesh** (`_app` NOLOGIN owner / `_user` LOGIN runtime / `_seed_runner` / `_migrator` LOGIN CREATEROLE) — Flyway migrates as a privileged migrator, the pool serves as the non-superuser `_user`.
- The bypass lesson + **why the audit is a static config audit in production** (a Testcontainers/integration check connects as the test superuser and would pass while prod stays vulnerable) — and why this showcase additionally does a live runtime audit (because here the pool is deliberately the non-super role).

---

## Phase SP1 — `tenant-isolation` (copy-and-refactor)

> Execution model: the security cluster (proxy, context, ids, policy SQL, role SQL, audit) is sanitized directly by the controller (Opus judgment — secret-scrub correctness + security-logic fidelity). Subagents do spec + quality review after each task. Mechanical demo glue (entity/repo/wiring) may go to Sonnet.

> TDD note: DB-enforced behavior. Build the cluster + wiring (compile-verified), then the behavior tests are the red→green checkpoint.

- [ ] **Task 5 — Module build file + Boot config root + JSpecify.** `tenant-isolation/build.gradle.kts` (data-jpa, flyway-core, flyway-database-postgresql, postgresql runtime, `org.jspecify:jspecify`, test: boot-starter-test + testcontainers junit-jupiter + postgresql). Uncomment `include("tenant-isolation")`. `TenantIsolationApplication.java`. Verify `:tenant-isolation:compileJava`.
- [ ] **Task 6 — Copy + sanitize the typed-ID + context cluster.** `TenantId`, `SystemTenantBoundary`, `TenantBindingScope`, `TenantIds` (neutral ACME/GLOBEX/SYSTEM_OPS + fresh UUIDs), `TenantContext`. Apply the package + identifier transforms from the inventory. Verify compile + a tiny `TenantContextTest` (fail-closed `requireCurrent` throws; `runAs` restores prior).
- [ ] **Task 7 — Copy + sanitize the proxy.** `TenantBindingObserver` (seam) + `TenantSessionDataSourceProxy` (de-Micrometer'd, all security logic intact). Verify compile.
- [ ] **Task 8 — Schema migration + neutral aggregate + wiring.** `V1__tenant_isolation.sql` (document table + RLS policy from calendar), `DocumentEntity`, `DocumentRepository`, `DataSourceConfig` (Hikari wrapped by the proxy), `application.yaml`. Verify compile.
- [ ] **Task 9 — Test base + role mesh.** `src/test/resources/db/init-roles.sql` (sanitized 4-tier mesh, password literal deleted), `testfixtures/WithTenant.java`, `AbstractRlsTest.java` (Testcontainers `postgres:16-alpine` + `withInitScript`, runtime pool wired as `tenant_user`, superuser seed helper). Verify `compileTestJava`.
- [ ] **Task 10 — RLS isolation tests (red→green).** `RlsIsolationTest`: cross-tenant SELECT returns zero; author sees own row; SYSTEM_OPS bypass sees all; cross-tenant write rejected; unbound borrow fails closed. Run `:tenant-isolation:test --tests '*RlsIsolationTest'`.
- [ ] **Task 11 — Pool-identity audit test.** `PoolIdentityAuditTest`: live `current_user` is non-superuser + non-bypass. Run it; then full module suite.
- [ ] **Task 12 — Module README.** Narrative + the bypass lesson + the static-yaml-vs-runtime audit nuance + run instructions.
- [ ] **Task 13 — Full build green + forbidden-token gate.** `./gradlew clean build`; then grep the whole repo for the forbidden tokens (must be zero); `git status` clean.

---

## Verification

- `./gradlew build` green from a clean clone (JDK 21 + Docker).
- `:tenant-isolation:test` passes: cross-tenant isolation, SYSTEM_OPS bypass, cross-tenant write rejection, fail-closed borrow, pool-identity audit.
- Forbidden-token grep over the whole repo returns nothing (Task 13).
- `git log -p` shows no commit ever contained a forbidden token (scrub-before-commit honored).

## Self-Review

- **Spec coverage:** buildable (T5,13), modular+portable (composite+per-module), five-layer spine (ADR-0001), tenant-isolation flagship incl. real bypass lesson (T6-12, ADR-0002, audit test), copy-and-refactor strategy with explicit sanitization inventory, scrub-before-commit + forbidden-token gate, no remote push. ✓
- **Placeholder scan:** transforms are concrete (package, identifier, secret-deletion, domain-neutralization rules); SP0 exact contents pinned to git `594f648` + the two deltas. ✓
- **Name consistency:** `tenant_*` roles, `app.current_tenant`/`app.bypass_rls` GUCs, `p_tenant_isolation`, `document` table, `TenantId`/`TenantContext`/`TenantIds`/`TenantSessionDataSourceProxy`/`TenantBindingObserver`, `io.github.joshuamatosdev.security.tenant`. ✓
- **Known risk:** Spring Boot `3.5.6` pin must resolve; bump to latest `3.5.x` if not (fix-forward).
