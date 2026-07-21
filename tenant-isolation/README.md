# Tenant Isolation

Tenant-aware datasource infrastructure for PostgreSQL-backed services. The
module demonstrates tenant placement. You choose placement through
configuration. Database-side controls stay fail-closed.

It covers Layer 5, data isolation, in the repository's composed security posture.

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

The suite starts PostgreSQL 18 containers. It verifies three placement modes.
Those are ID, schema, and database.

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

The starter imports reference datasource configuration. It runs when
`tenant.isolation.enabled` is true. Absent counts as true. Disable it
with:

```yaml
tenant:
  isolation:
    enabled: false
```

## Implementation Walkthrough

This is the full walkthrough. It covers tenant and organization. It uses the
modules as published. You own four things. The starter ships everything else.
Every step is real code. It compiles as a consumer app. Tests cover it. Find it
in [`examples/tenant-isolation-spring-boot`](../examples/tenant-isolation-spring-boot/):

```bash
./gradlew -p examples/tenant-isolation-spring-boot test
```

### 1. Depend

```kotlin
implementation("io.github.joshuamatosdev.security:tenant-isolation-spring-boot-starter:0.1.0-SNAPSHOT")
implementation("io.github.joshuamatosdev.security:authorization-spring-boot-starter:0.1.0-SNAPSHOT") // optional, for org-scoped authz decisions
testImplementation("io.github.joshuamatosdev.security:tenant-isolation-testkit:0.1.0-SNAPSHOT")
```

The tenant starter auto-replaces your `DataSource`. It installs the
claim-binding proxy. You can define your own instead. Then it backs off.

### 2. Configure

```yaml
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_RUNTIME_USER}      # NOSUPERUSER NOBYPASSRLS role
    password: ${DB_RUNTIME_PASSWORD}
  jpa:
    database-platform: org.hibernate.dialect.PostgreSQLDialect
    hibernate:
      ddl-auto: none                  # your migrations own the schema
    open-in-view: false
    properties:
      hibernate:
        boot:
          allow_jdbc_metadata_access: false
tenant:
  isolation:
    mode: id                          # shared tables + RLS
  binding:
    claim-secret: ${TENANT_BINDING_CLAIM_SECRET}
    system-ops-password: ${TENANT_BINDING_SYSTEM_OPS_PASSWORD}
    organization-scope: optional      # off -> optional -> required
    claim-ttl: 2m                     # exceed the longest connection hold time
```

The `spring.jpa` block is load-bearing. It is not styling. The starter's
classpath includes JPA. Hibernate makes a boot-time metadata connection. It
borrows from the tenant-bound proxy. But no tenant is bound. So the borrow fails
closed. That aborts startup. Two settings remove that boot-time borrow. Set
`allow_jdbc_metadata_access: false`. Also set an explicit dialect.

`organization-scope` is the org rollout dial. `off` means tenant-only.
`optional` flows the org claim. It flows only when bound. Adopt policies while
old callers work. `required` fails an org-less borrow closed. This applies to an
ordinary tenant.

### 3. Write one filter — the only code you own

Use your **verified** token. Read both IDs from it. Never use a client-writable
header. Bind them atomically. The filter is compiled and tested. See
[`TenantBindingFilter.java`](../examples/tenant-isolation-spring-boot/src/main/java/example/TenantBindingFilter.java).
It lives in the example app. Non-JWT requests pass through. An unbound borrow
fails closed anyway. A JWT may lack `tenant_id`. Then it is rejected with 403.
Otherwise it binds the tenant. It adds `organization_id` when present. It uses the injected
`tenantContext.runAs(...)`. This wraps the remaining chain.

You get key properties for free. Org can never bind without tenant. No API
allows it. `runAs` restores the prior binding. Switching tenant or org is
rejected. This applies inside an open transaction. A borrow with no context
throws. It throws before any SQL runs. Everything downstream stays untouched.
That means JPA repositories and `JdbcTemplate`. Raw JDBC too. The proxy acts on
every borrow. It signs and binds `app.tenant_claim`. That claim looks like
`v2:...`. When bound, it adds `app.org_claim`. That one looks like `v2o:...`.
Close resets both claims.

Some jobs must cross tenants. These are platform or admin jobs. They use
`tenantContext.runAsSystemOps(work)`. It uses a read-only pool. It never carries
an org. Some backfills assign orgs to rows. These rows were unassigned. They run
org-unscoped. Use `tenantContext.runAs(tenant, work)`.

### 4. Own the database side

Copy the reference DDL to migrations. It comes from
[`src/test/resources/db/init.sql`](src/test/resources/db/init.sql). Adapt it per
table. A complete adapted copy exists. It keeps the same roles. It keeps the
verifiers and policies. They apply to a `note` table. That is the adopter's own
table. See the example app's
[`db/init.sql`](../examples/tenant-isolation-spring-boot/src/test/resources/db/init.sql).

1. Roles. The runtime role is `NOSUPERUSER NOBYPASSRLS`. `tenant_bypass` is a
   NOLOGIN marker. Only the ops role gets it.
2. Secret. Install the `tenant_security.claim_secret` row. It comes from secret
   management. Use the same value as `tenant.binding.claim-secret`.
3. Verifiers. Add `tenant_security.current_tenant_id()` and `current_org_id()`.
   Both HMAC-verify and expiry-check. Kind markers separate them. The markers
   are `v2` and `v2o`. The claims can't be swapped.
4. Per tenant-scoped table:

```sql
ALTER TABLE your_table ADD COLUMN tenant_id uuid NOT NULL DEFAULT tenant_security.current_tenant_id();
ALTER TABLE your_table ADD COLUMN organization_id uuid DEFAULT tenant_security.current_org_id();
ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;
ALTER TABLE your_table FORCE ROW LEVEL SECURITY;
-- permissive tenant policy + RESTRICTIVE org cap: copy p_tenant_isolation and
-- p_organization_scope from init.sql verbatim, table name swapped
```

The `ADD COLUMN ... NOT NULL DEFAULT` form is simple. It suits new or empty
tables. A migration binds no tenant claim. So the default evaluates NULL. This
happens on a populated table. It fails the NOT NULL constraint. Retrofit an
existing table carefully. Use three steps. First add the column nullable. Then
backfill `tenant_id` per tenant. Use your ownership data. Finally run
`ALTER TABLE your_table ALTER COLUMN tenant_id SET NOT NULL`.

Here are the semantics. An org-bound session is scoped. It reads and writes org
rows. It sees only its own org. An org-unscoped session sees more. It sees the
whole tenant. Org **subdivides** tenancy. It never replaces it. Some rows have
`organization_id` NULL. Those are tenant-admin material. The database stamps
both columns. It uses the verified claims. Application code can't set them. It
can't forget them. It can't lie about them.

### 5. Authorization layer (org-aware decisions, optional)

The data plane above filters *rows*.
[`authorization`](../authorization/README.md) handles endpoint and resource
decisions. Its `RequestContext` carries two dimensions. They match the data
plane's. Those are `tenantId` and `organizationId`. It also carries org-scoped
`RoleAssignment`s. Build it in the same filter. Use the same token. Call
`AuthorizationService.enforce(...)`. Do it in your service layer. One request
identity feeds both planes. They can't disagree.

### What you never write

You write none of these. No per-entity annotations. No `@Filter`s. No
`WHERE tenant_id` predicates. No `organization_id` predicates either. None
anywhere. The testkit helps you prove this. Follow the
`OrganizationScopeRlsIsolationTest` pattern. Prove it in your own CI. Your
repository has zero predicates. Isolation still holds. It holds against real
PostgreSQL. The example app proves it too. See
[`TenantIsolationFlowTest`](../examples/tenant-isolation-spring-boot/src/test/java/example/TenantIsolationFlowTest.java).
It runs the proof over HTTP. Two tenants and two organizations. One
zero-predicate controller handles them.

## What It Demonstrates

- Typed Spring configuration selects placement.
- Signed session claims on every borrow.
- An organization dimension binds atomically. It binds with the tenant. It emits
  a second signed claim. The claim is kind-separated. A RESTRICTIVE row policy
  caps it.
- Explicit, revocable cross-tenant read entitlements. A platform-administered
  grant ledger backs them. A SELECT-only policy applies. So sharing never widens
  writes.
- Connection reset before pool return.
- Non-superuser runtime roles with `NOBYPASSRLS`.
- A separate read-only system-ops pool. It serves ID-mode cross-tenant reads.
- A separate sentinel-pinned system-writer role. It handles system-owned writes.
  A RESTRICTIVE policy caps it.
- Forced signed-claim RLS guards schema-mode tables. It is a second guard.
- Database-owned UUIDv7 identifiers through PostgreSQL 18.
- Build-breaking tests catch unsafe pool identities. They catch tenant-boundary
  mistakes too.

## Isolation Modes

The active strategy is selected with:

```yaml
tenant:
  isolation:
    mode: id       # id, schema, or database
```

### ID Mode

`id` is the default mode. It uses shared tables. It uses a `tenant_id` column.
It forces PostgreSQL Row-Level Security. It adds a signed `app.tenant_claim`
setting.

Required runtime values:

- `SPRING_DATASOURCE_URL`
- `SPRING_DATASOURCE_USERNAME`
- `SPRING_DATASOURCE_PASSWORD`
- `TENANT_BINDING_CLAIM_SECRET`
- `TENANT_BINDING_SYSTEM_OPS_PASSWORD`

`tenant.binding.system-ops-password` is required in ID mode. It protects the
read-only system-ops pool. That pool needs its own password. It won't inherit
the runtime password.

### Schema Mode

`schema` mode keeps one database. It selects a tenant schema. An allowlisted
placement map drives that.

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

Schema mode rejects three cases. It rejects missing tenants. It rejects unknown
tenants. It rejects the ambient system-ops tenant. Operational cross-tenant
reads need another path. Iterate explicit tenant placements. Or use a reporting
store.

The reference DDL adds forced RLS. It covers each tenant schema's table. This
matters for one case. One role may span many schemas. Schema selection on borrow
is placement. It is not a full boundary. Ordinary SQL can retarget `search_path`.
It can qualify another schema. The signed tenant claim still guards. It is the
database-side guard.

### Database Mode

`database` mode selects a JDBC pool. The pool is tenant-specific. Configuration
drives the choice.

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

Do not commit real database passwords. Bind them from environment variables. Or
from secret management.

## Signed Tenant Claims

All modes bind the signed claim. This is defense in depth. ID mode uses it for
RLS. Schema mode uses it broadly. It sets table defaults. It runs tenant checks.
It forces RLS in reference DDL. Database mode still binds it. Then defaults can
verify it. Constraints can verify it too. Optional RLS policies can too. They
check which tenant was selected.

The claim format is:

```text
v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac>
```

The HMAC covers:

```text
v2:<tenant_uuid>:<exp_epoch_seconds>
```

Ordinary SQL can change custom settings. These are PostgreSQL custom settings.
So the database distrusts `app.tenant_claim`. It never trusts it directly. The
verifier must recompute the HMAC. The claim must not be expired. Only then is
the tenant accepted.

Claims are minted after a physical or pooled connection is acquired, so pool
wait time does not consume their lifetime. `tenant.binding.claim-ttl` defaults
to two minutes and must be at least one second. Set it above the application's
longest connection hold time, including its longest statement or transaction,
while keeping it as short as practical to limit replay exposure.

## Organization Scope

Organizations subdivide a tenant. Think teams, departments, workspaces. The
tenant stays the outer boundary. The organization scopes rows within it.
The organization binding is a co-equal, optional dimension inside the tenant boundary.

Select the posture with:

```yaml
tenant:
  binding:
    organization-scope: off   # off (default), optional, or required
```

- `off` — tenant-only binding. Existing adopters see no change.
- `optional` — emits a second signed claim. The claim is `app.org_claim`. It
  emits for a bound organization. This is the migration posture.
- `required` — one borrow fails closed. That is an ordinary tenant borrow. It
  carries no organization. It fails before taking a connection. The system-ops
  tenant is exempt. Its cross-tenant work carries no organization.

Bind the organization atomically. Bind it with the tenant. No entry point binds
it alone:

```java
tenantContext.runAs(tenantId, organizationId, work);
```

This is the organization claim. It has its own kind marker. The marker sits
inside the payload. The payload is `v2o:<organization_uuid>:<exp>:<hmac>`. So the
two claims stay separate. Neither satisfies the other's verifier. They still
share one secret. The reference DDL verifies the claim. It uses
`tenant_security.current_org_id()`. A `RESTRICTIVE` policy adds a cap. It
AND-combines with the tenant policy. An organization-bound session is narrow. It
reads and writes org rows. Only its own organization's rows. An
organization-unscoped session sees more. It keeps whole-tenant visibility. Some
rows have no organization. Those stay tenant-admin material. `organization_id` is
stamped by column default. It comes from the verified claim. This works exactly
like `tenant_id`.

## Cross-Tenant Read Entitlements

Sometimes the platform brokers sharing. The sharing crosses the tenant boundary.
It is deliberate. Think a licensed dataset. Or a paid cross-region read. An
entitlement is an explicit grant. It is a grant row. It is not a wider identity.
The grant ledger is explicit, expiring, and read-only for ordinary tenant traffic.

The reference DDL holds grant rows. They live in `tenant_security.read_grant`.
Each row has four columns. They are
`(grantor_tenant_id, grantee_tenant_id, resource_class, expires_at)`. A second
permissive policy opens reads:

```sql
CREATE POLICY p_entitled_read ON document
    AS PERMISSIVE
    FOR SELECT TO public
    USING (tenant_security.has_read_grant(tenant_id, 'document'));
```

Properties the tests hold executable:

- **Read-only by structure.** The policy covers `SELECT` only. So foreign rows
  stay invisible. That holds for INSERT, UPDATE, DELETE.
- **Directional, class-scoped, expiring, revocable.** Consider a
  `globex`-to-`acme` grant. It opens nothing in reverse. It opens nothing outside
  its class. It stops at expiry. It stops on row delete. This takes effect next
  statement. No claim TTL to wait out.
- **Unforgeable and confidential.** Ordinary tenant roles hold no privilege. That
  covers the grant ledger. Consider hostile SQL in a session. It cannot entitle
  itself. It cannot enumerate sharing pairs. One window exists only. It is the
  `has_read_grant` check. That check is `SECURITY DEFINER`. It answers only for
  one tenant. That is the session's verified tenant.
- **No session-state change.** No new claim appears. No context change happens.
  Grants are just data. The organization cap scopes one tenant. It scopes the
  reader's own tenant. So an organization-bound session is fine. It keeps its
  entitled foreign reads.

## Pool Identity

RLS policy is not enough alone. The connection pool's role matters too. That
PostgreSQL role is a control.

A superuser bypasses RLS completely. This happens unconditionally. Three things
skip a superuser. `FORCE ROW LEVEL SECURITY` does not apply. The policy does not
apply. The signed claim does not apply. Runtime traffic needs a dedicated role.
Use `NOSUPERUSER NOBYPASSRLS`.

`PoolIdentityAuditTest` enforces this invariant. It breaks the build on
violation. This covers the reference ID-mode pool.

## Testing

Run all tenant-isolation tests:

```bash
../gradlew :tenant-isolation:test
```

Important tests:

- `RlsIsolationTest` covers ID-mode RLS behavior. It rejects forged claims. It
  checks database-stamped `tenant_id`. It checks UUIDv7 primary keys. It checks
  system-ops read-only access. It proves fail-closed unbound access.
- `OrganizationScopeRlsIsolationTest` covers organization scope. Bound reads and
  writes stay inside. They stay inside the organization. Unscoped sessions keep
  whole-tenant visibility. It checks claim-kind separation. That is `v2` vs
  `v2o`. It checks database-stamped `organization_id`. Repository code has no
  organization predicate.
- `CrossTenantReadEntitlementTest` covers entitled reads. They open the granted
  rows. They open exactly those rows. Grants are directional and class-scoped.
  They expire and stay revocable. They are never writable. A tenant session
  cannot mint grants. It cannot enumerate them either.
- `SchemaIsolationModeIntegrationTest` covers schema placement. It checks signed
  claim binding. It checks physical tenant separation. It guards against
  `search_path` retargeting. This happens in PostgreSQL.
- `DatabaseIsolationModeIntegrationTest` covers per-tenant routing. It checks
  signed claim binding. It checks hidden pool inspection. It checks physical
  tenant separation.
- `PoolIdentityAuditTest` covers role invariants. It checks non-superuser roles.
  It checks `NOBYPASSRLS` roles.
- `SystemWriterRestrictivePolicyTest` covers the system-writer tier. It checks
  sentinel-claim minting. A RESTRICTIVE write cap applies. It rejects a captured
  foreign claim. Even a valid one is rejected. It checks the ungranted
  system-write path. This covers the runtime pool.
- `SystemTenantBoundaryArchitectureTest` is a source-level guard. It guards
  system-ops boundary access.

## Documentation

- [Thread context protection](docs/thread-context-protection.md)
- [Glossary](../docs/GLOSSARY.md)
