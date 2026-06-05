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
- [What It Demonstrates](#what-it-demonstrates)
- [Isolation Modes](#isolation-modes)
- [Signed Tenant Claims](#signed-tenant-claims)
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
`glyptodon.tenant-isolation.enabled` is true or absent. Disable it with:

```yaml
glyptodon:
  tenant-isolation:
    enabled: false
```

## What It Demonstrates

- Tenant placement selected from typed Spring configuration.
- Signed PostgreSQL session claims on every connection borrow.
- Connection reset before a pooled connection is returned.
- Non-superuser runtime roles with `NOBYPASSRLS`.
- A separate read-only system-ops pool for ID-mode cross-tenant reads.
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
- `SchemaIsolationModeIntegrationTest`: schema placement, signed claim binding,
  physical tenant separation, and protection against `search_path` retargeting
  in PostgreSQL.
- `DatabaseIsolationModeIntegrationTest`: per-tenant database routing, signed
  claim binding, hidden pool inspection, and physical tenant separation.
- `PoolIdentityAuditTest`: non-superuser and `NOBYPASSRLS` role invariants.
- `SystemTenantBoundaryArchitectureTest`: source-level guard for system-ops
  boundary access.

## Documentation

- [Thread context protection](docs/thread-context-protection.md)
- [ADR-0002](../docs/adr/0002-tenant-isolation-rls-session-binding.md)
- [Glossary](../docs/GLOSSARY.md)
