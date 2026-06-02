# ADR-0002: Tenant Isolation — Row-Level Security + Session Binding

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

In a shared-schema multi-tenant database, every row carries a `tenant_id`. If
isolation depends on application code remembering to add `WHERE tenant_id = ?`,
a single missing predicate — or any path that bypasses the ORM (native query,
raw JDBC, a replication slot, a `pg_dump`) — leaks across tenants. The boundary
must live where the data lives.

## Decision

Enforce tenant isolation in PostgreSQL with Row-Level Security, bound to a
per-connection session variable.

### Database

Every tenant-scoped table:

```sql
ALTER TABLE document
    ALTER COLUMN tenant_id SET DEFAULT current_setting('app.current_tenant', true)::uuid;
ALTER TABLE document ENABLE ROW LEVEL SECURITY;
ALTER TABLE document FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant_isolation ON document
    FOR ALL TO public
    USING (
        tenant_id = current_setting('app.current_tenant', true)::uuid
        OR current_setting('app.bypass_rls', true) = 'on'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant', true)::uuid
        OR current_setting('app.bypass_rls', true) = 'on'
    );
```

- `ENABLE` + `FORCE` — `FORCE` subjects even the table owner to the policy.
- `USING` filters reads; `WITH CHECK` (same expression) rejects cross-tenant
  **writes**, not just reads.
- The `tenant_id` column **defaults from the session GUC**, so an insert is
  stamped with the active tenant — the caller cannot forget to set it, and
  cannot set someone else's (the `WITH CHECK` rejects a mismatched explicit value).
- `app.bypass_rls = 'on'` is a deliberate, audited escape for a system-operations
  context (cross-tenant observability, platform rollups). It is set only for one
  well-known system tenant, never for an ordinary request.

### Application

A `DataSource` proxy binds the session on **every connection borrow** from the
request-scoped tenant context:

- Inside an active physical transaction, bindings are transaction-local
  (`set_config(..., true)`) and clear automatically at commit/rollback.
- Otherwise they are session-scoped and the returned connection is wrapped so
  `close()` clears the settings before the connection returns to the pool.
- **Fail-closed:** if a tenant-scoped pool is borrowed with no tenant in
  context, the borrow throws before any SQL can run.

### The role mesh — and why it is the crux

`FORCE ROW LEVEL SECURITY` forces the table *owner* through the policy. It does
**not** force a **superuser**, and it does not force a role with `BYPASSRLS`. A
PostgreSQL superuser bypasses RLS unconditionally — regardless of `FORCE`,
regardless of the policy, regardless of the GUC. Local/dev database images
commonly authenticate as the bootstrap superuser, which silently disables
isolation even with perfect DDL.

So the runtime database identity is structural, not incidental. Each database
uses a 4-tier role mesh:

| Tier | Attributes | Role |
|---|---|---|
| owner | `NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT` | `tenant_app` — owns the schema |
| runtime | `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT`, member of `tenant_app` | `tenant_user` — the connection pool |
| seed | `LOGIN`, narrow grants | `tenant_seed_runner` |
| migrator | `LOGIN NOSUPERUSER NOBYPASSRLS CREATEROLE`, member of `tenant_app` | `tenant_migrator` — Flyway runs DDL here |

The connection pool connects as `tenant_user` — never a superuser, never
`BYPASSRLS`. Migrations run as the distinct `tenant_migrator`. This separation is
what makes the policy actually engage at runtime.

### Auditing the role attribute

This was a real finding: with correct DDL in place, isolation was silently
bypassed in a development environment because the pool connected as the bootstrap
superuser. The fix is structural (the pool identity), and it is guarded by a
test.

There is a subtlety in *how* you test it. An integration test that spins up a
throwaway PostgreSQL connects as that container's bootstrap superuser — so an
integration-time role check would **pass in CI while production stays
vulnerable**. The production guard is therefore a **static audit of the datasource
configuration** that ships with the artifact: it fails if any pool is configured
with a known superuser/bypass identity, regardless of which database a test
happens to point at.

This showcase module additionally asserts a **live runtime audit** (the
connected `current_user` is `NOSUPERUSER NOBYPASSRLS`) — meaningful here because
the demo deliberately wires the pool as the non-superuser `tenant_user`. The two
techniques are complementary; the module README explains when to use which.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Convention-only `WHERE tenant_id = ?` | Cannot be enforced structurally; one missing predicate is one leak. Kept only as defense-in-depth restatement. |
| Schema-per-tenant | Operational fan-out at scale (migrations, pool sizing). RLS scales without schema multiplication. |
| ORM-level filter (e.g. Hibernate `@Filter`) | Bypassed by native queries, raw JDBC, replication, and `pg_dump`. The database is the only complete boundary. |
| Correct policy, pool connects as superuser | Silently bypasses RLS — the policy becomes decorative. The role attribute is part of the control, not an ops detail. |

## Consequences

- A query without tenant scoping returns nothing rather than leaking — the
  failure mode is empty, not cross-tenant.
- Cross-tenant **writes** are rejected by the database, and the tenant column is
  stamped from the session, so a forged `tenant_id` is impossible through the pool.
- System-operations access is explicit (`app.bypass_rls`), scoped to one
  well-known tenant, and auditable — not an ambient capability.
- The pool's non-superuser identity is a tested invariant, enforced by a static
  configuration audit (production) and a live runtime audit (this module).
