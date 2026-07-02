# Tenant Isolation

Tenant-aware datasource infrastructure for PostgreSQL-backed services. The
module demonstrates how to choose tenant placement through configuration while
keeping database-side controls fail-closed.

It covers Layer 5, data isolation, in the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The
decision record is
[ADR-0002](../docs/adr/0002-tenant-isolation-rls-session-binding.md).

## Table of Contents

- [Quick Start](#quick-start)
- [Library Artifacts](#library-artifacts)
- [Implementation Walkthrough](#implementation-walkthrough)
- [What It Demonstrates](#what-it-demonstrates)
- [Isolation Modes](#isolation-modes)
- [Signed Tenant Claims](#signed-tenant-claims)
- [Organization Scope](#organization-scope)
- [Cross-Tenant Read Entitlements](#cross-tenant-read-entitlements)
- [Pool Identity](#pool-identity)
- [Testing](#testing)
- [Documentation](#documentation)

## Quick Start

Requirements:

- JDK 21
- Docker, for PostgreSQL Testcontainers

Run the module tests:

```bash
../gradlew :tenant-isolation:test
```

The suite starts PostgreSQL 18 containers and verifies ID, schema, and database
placement modes.

## Library Artifacts

Plain Java or custom Spring wiring:

```kotlin
implementation("io.github.joshuamatosdev.security:tenant-isolation:0.1.0-SNAPSHOT")
testImplementation("io.github.joshuamatosdev.security:tenant-isolation-testkit:0.1.0-SNAPSHOT")
```

Spring Boot auto-configuration:

```kotlin
implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
```

The starter imports the reference data-source configuration when
`bulwark.tenant-isolation.enabled` is true or absent. Disable it with:

```yaml
bulwark:
  tenant-isolation:
    enabled: false
```

## Implementation Walkthrough

Full walkthrough — tenant + organization, using the modules as published. Four
things you own; everything else ships in the starter.

### 1. Depend

```kotlin
implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
implementation("io.github.joshuamatosdev.security:layered-authorization-spring-boot-starter:0.1.0-SNAPSHOT") // optional, for org-scoped authz decisions
testImplementation("io.github.joshuamatosdev.security:tenant-isolation-testkit:0.1.0-SNAPSHOT")
```

The tenant starter auto-replaces your primary `DataSource` with the
claim-binding proxy (backs off if you define your own).

### 2. Configure

```yaml
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_RUNTIME_USER}      # NOSUPERUSER NOBYPASSRLS role
    password: ${DB_RUNTIME_PASSWORD}
tenant:
  isolation:
    mode: id                          # shared tables + RLS
  binding:
    claim-secret: ${TENANT_BINDING_CLAIM_SECRET}
    system-ops-password: ${TENANT_BINDING_SYSTEM_OPS_PASSWORD}
    organization-scope: optional      # off -> optional -> required
```

`organization-scope` is the whole org rollout dial: `off` = tenant-only,
`optional` = org claim flows when bound (adopt policies while old callers still
work), `required` = borrow fails closed if an ordinary tenant binds no org.

### 3. Write one filter — the only code you own

Resolve both IDs from your **verified** token (never a client-writable header),
bind atomically:

```java
@Component
class TenantBindingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        Jwt jwt = ((JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication()).getToken();
        TenantId tenant = TenantId.fromString(jwt.getClaimAsString("tenant_id"));
        String org = jwt.getClaimAsString("organization_id");
        Runnable work = () -> { try { chain.doFilter(req, res); } catch (Exception e) { throw new IllegalStateException(e); } };
        if (org == null) TenantContext.runAs(tenant, work);
        else TenantContext.runAs(tenant, OrganizationId.fromString(org), work);
    }
}
```

Key properties you get for free: org can never bind without tenant (no API for
it), `runAs` restores the prior binding, switching tenant *or* org inside an
open transaction is rejected, and a borrow with no context throws before any
SQL runs. Everything downstream — JPA repositories, `JdbcTemplate`, raw JDBC —
stays untouched: on every connection borrow the proxy signs and binds
`app.tenant_claim` (`v2:...`) and, when bound, `app.org_claim` (`v2o:...`);
close resets both.

Platform/admin jobs that must cross tenants:
`TenantContext.runAsSystemOps(work)` — read-only pool, never carries an org.
Backfills that assign orgs to unassigned rows run org-unscoped:
`TenantContext.runAs(tenant, work)`.

### 4. Own the database side

Copy the reference DDL from
[`src/test/resources/db/init.sql`](src/test/resources/db/init.sql) into your
migrations, adapted per table:

1. Roles: runtime role `NOSUPERUSER NOBYPASSRLS`; `tenant_bypass` (NOLOGIN
   marker) granted only to the ops role.
2. Secret: `tenant_security.claim_secret` row installed from secret
   management — same value as `tenant.binding.claim-secret`.
3. Verifiers: `tenant_security.current_tenant_id()` and `current_org_id()`
   (both HMAC-verify + expiry-check; kind markers `v2`/`v2o` mean the claims
   can't be swapped).
4. Per tenant-scoped table:

```sql
ALTER TABLE your_table ADD COLUMN tenant_id uuid NOT NULL DEFAULT tenant_security.current_tenant_id();
ALTER TABLE your_table ADD COLUMN organization_id uuid DEFAULT tenant_security.current_org_id();
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE your_table FORCE ROW LEVEL SECURITY;
-- permissive tenant policy + RESTRICTIVE org cap: copy p_tenant_isolation and
-- p_organization_scope from init.sql verbatim, table name swapped
```

Semantics: an org-bound session reads/writes only its org's rows; an
org-unscoped session sees the whole tenant (org **subdivides** tenancy, never
replaces it); rows with `organization_id` NULL are tenant-admin material. Both
columns are DB-stamped from the verified claims — application code can't set
them, forget them, or lie about them.

### 5. Authorization layer (org-aware decisions, optional)

The data plane above filters *rows*. For endpoint/resource decisions,
[`layered-authorization`](../layered-authorization/README.md)'s
`RequestContext` carries the same two dimensions (`tenantId`,
`organizationId`, org-scoped `RoleAssignment`s) — build it in the same filter
from the same token, call `AuthorizationService.enforce(...)` in your service
layer. One request identity feeds both planes; they can't disagree.

### What you never write

Per-entity annotations, `@Filter`s, or `WHERE tenant_id`/`organization_id`
predicates — anywhere. The testkit plus the pattern of
`OrganizationScopeRlsIsolationTest` let you prove that in your own CI:
repository with zero predicates, isolation still holds against real
PostgreSQL.

## What It Demonstrates

- Tenant placement selected from typed Spring configuration.
- Signed PostgreSQL session claims on every connection borrow.
- An organization dimension bound atomically with the tenant, emitted as a
  second kind-separated signed claim, and capped by a RESTRICTIVE row policy.
- Explicit, revocable cross-tenant read entitlements: a platform-administered
  grant ledger and a SELECT-only policy, so sharing never widens writes.
- Connection reset before a pooled connection is returned.
- Non-superuser runtime roles with `NOBYPASSRLS`.
- A separate read-only system-ops pool for ID-mode cross-tenant reads.
- A separate sentinel-pinned system-writer role for system-owned writes, capped by a RESTRICTIVE policy.
- Forced signed-claim RLS as a second guard for schema-mode tables.
- Database-owned UUIDv7 identifiers through PostgreSQL 18.
- Build-breaking tests for unsafe pool identities and tenant-boundary mistakes.

## Isolation Modes

The active strategy is selected with:

```yaml
tenant:
  isolation:
    mode: id       # id, schema, or database
```

### ID Mode

`id` is the default mode. It uses shared tables, a `tenant_id` column, forced
PostgreSQL Row-Level Security, and a signed `app.tenant_claim` session setting.

Required runtime values:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `TENANT_BINDING_CLAIM_SECRET`
- `TENANT_BINDING_SYSTEM_OPS_PASSWORD`

`tenant.binding.system-ops-password` is required in ID mode so the read-only
system-ops pool cannot silently inherit the ordinary runtime password.

### Schema Mode

`schema` mode keeps one database and selects a tenant schema from an allowlisted
placement map.

```yaml
tenant:
  binding:
    claim-secret: ${TENANT_BINDING_CLAIM_SECRET}
  isolation:
    mode: schema
    schema:
      tenants:
        acme:
          id: 0190a000-0000-7000-8000-0000000000a1
          schema: tenant_acme
```

See [application-schema.yaml](src/main/resources/application-schema.yaml).

Schema mode rejects missing tenants, unknown tenants, and the ambient system-ops
tenant. Operational cross-tenant reads should iterate explicit tenant
placements or use a reporting store.

The reference schema-mode DDL also enables forced RLS on each tenant schema's
table. This matters when one runtime role has privileges in more than one tenant
schema: schema selection on borrow is placement, not a complete security
boundary, because ordinary SQL can retarget `search_path` or qualify another
schema. The signed tenant claim remains the database-side guard.

### Database Mode

`database` mode selects a tenant-specific JDBC pool from configuration.

```yaml
tenant:
  binding:
    claim-secret: ${TENANT_BINDING_CLAIM_SECRET}
  isolation:
    mode: database
    database:
      tenants:
        acme:
          id: 0190a000-0000-7000-8000-0000000000a1
          jdbc-url: ${TENANT_ACME_JDBC_URL}
          username: ${TENANT_ACME_USERNAME}
          password: ${TENANT_ACME_PASSWORD}
          pool-name: tenant-db-acme
```

See [application-database.yaml](src/main/resources/application-database.yaml).

Do not commit real database passwords. Bind them from environment variables or
secret management.

## Signed Tenant Claims

All modes bind the signed tenant claim as defense in depth. ID mode uses it for
RLS. Schema mode uses it for table defaults, tenant checks, and forced RLS in
the reference DDL. Database mode still binds it so database defaults,
constraints, or optional RLS policies can verify which tenant the application
selected.

The claim format is:

```text
v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac>
```

The HMAC covers:

```text
v2:<tenant_uuid>:<exp_epoch_seconds>
```

PostgreSQL custom settings are mutable by ordinary SQL, so the database never
trusts `app.tenant_claim` directly. It accepts the tenant only when the verifier
can recompute the HMAC and the claim has not expired.

## Organization Scope

Organizations subdivide a tenant (teams, departments, workspaces). The tenant
stays the outer isolation boundary; the organization scopes rows within it.
[ADR-0007](../docs/adr/0007-organization-scope-within-tenant-isolation.md) is
the decision record.

Select the posture with:

```yaml
tenant:
  binding:
    organization-scope: off   # off (default), optional, or required
```

- `off` — tenant-only binding; nothing changes for existing adopters.
- `optional` — the proxy emits a second signed claim, `app.org_claim`, whenever
  the binding carries an organization. This is the migration posture.
- `required` — an ordinary tenant borrow without an organization fails closed
  before a connection is taken. The system-ops tenant is exempt because
  cross-tenant operational work carries no organization.

Bind the organization atomically with the tenant — there is no entry point that
binds an organization alone:

```java
TenantContext.runAs(tenantId, organizationId, work);
```

The organization claim has its own kind marker inside the signed payload
(`v2o:<organization_uuid>:<exp>:<hmac>`), so tenant and organization claims can
never satisfy each other's verifier even though they share one secret. In the
reference DDL, `tenant_security.current_org_id()` verifies the claim and a
`RESTRICTIVE` policy AND-combines with the tenant policy: an organization-bound
session reads and writes only its organization's rows, an organization-unscoped
session keeps whole-tenant visibility, and rows with no organization stay
tenant-admin material. `organization_id` is stamped by column default from the
verified claim, exactly like `tenant_id`.

## Cross-Tenant Read Entitlements

Sometimes the platform must broker deliberate sharing across the tenant
boundary — a licensed dataset, a paid cross-region read. An entitlement is an
explicit grant row, not a wider identity.
[ADR-0008](../docs/adr/0008-entitlement-cross-tenant-read-grants.md) is the
decision record.

In the reference DDL, `tenant_security.read_grant` holds
`(grantor_tenant_id, grantee_tenant_id, resource_class, expires_at)` rows, and
a second permissive policy adds the read path:

```sql
CREATE POLICY p_entitled_read ON document
    AS PERMISSIVE
    FOR SELECT TO public
    USING (tenant_security.has_read_grant(tenant_id, 'document'));
```

Properties the tests hold executable:

- **Read-only by structure.** The policy covers `SELECT` only, so foreign rows
  stay invisible to every INSERT, UPDATE, and DELETE plan.
- **Directional, class-scoped, expiring, revocable.** A grant from `globex` to
  `acme` opens nothing in the other direction, nothing outside its resource
  class, and stops working at expiry or on row delete — effective on the next
  statement, with no claim TTL to wait out.
- **Unforgeable and confidential.** Ordinary tenant roles hold no privilege on
  the grant ledger: hostile SQL inside a tenant session can neither entitle
  itself nor enumerate who shares with whom. The `SECURITY DEFINER`
  `has_read_grant` check is the only window, and it answers only for the
  session's verified tenant.
- **No session-state change.** No new claim and no context change — grants are
  data. The organization cap scopes the reader's own tenant, so an
  organization-bound session keeps its entitled foreign reads.

## Pool Identity

RLS policy is not enough by itself. The PostgreSQL role used by the connection
pool is part of the security control.

A superuser bypasses RLS unconditionally. `FORCE ROW LEVEL SECURITY`, the
policy, and the signed claim do not apply to a superuser. Runtime traffic must
use a dedicated `NOSUPERUSER NOBYPASSRLS` role.

`PoolIdentityAuditTest` makes this a build-breaking invariant for the reference
ID-mode pool setup.

## Testing

Run all tenant-isolation tests:

```bash
../gradlew :tenant-isolation:test
```

Important tests:

- `RlsIsolationTest`: ID-mode RLS behavior, forged claim rejection,
  database-stamped `tenant_id`, UUIDv7 primary keys, system-ops read-only access,
  and fail-closed unbound access.
- `OrganizationScopeRlsIsolationTest`: organization-bound reads and writes stay
  inside the organization, organization-unscoped sessions keep whole-tenant
  visibility, claim-kind separation (`v2` vs `v2o`), and database-stamped
  `organization_id` — with no organization predicate in repository code.
- `CrossTenantReadEntitlementTest`: entitled reads open exactly the granted
  rows — directional, class-scoped, expiring, revocable, never writable — and a
  tenant session can neither mint nor enumerate grants.
- `SchemaIsolationModeIntegrationTest`: schema placement, signed claim binding,
  physical tenant separation, and protection against `search_path` retargeting
  in PostgreSQL.
- `DatabaseIsolationModeIntegrationTest`: per-tenant database routing, signed
  claim binding, hidden pool inspection, and physical tenant separation.
- `PoolIdentityAuditTest`: non-superuser and `NOBYPASSRLS` role invariants.
- `SystemWriterRestrictivePolicyTest`: the system-writer tier — sentinel-claim
  minting, the RESTRICTIVE write cap that rejects even a captured valid
  foreign-tenant claim, and the ungranted system-write path for the runtime pool.
- `SystemTenantBoundaryArchitectureTest`: source-level guard for system-ops
  boundary access.

## Documentation

- [Thread context protection](docs/thread-context-protection.md)
- [ADR-0002](../docs/adr/0002-tenant-isolation-rls-session-binding.md)
- [Glossary](../docs/GLOSSARY.md)
