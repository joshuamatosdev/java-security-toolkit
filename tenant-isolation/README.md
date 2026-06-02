# tenant-isolation

PostgreSQL Row-Level Security + a session-bound `app.current_tenant`, served by a
**non-superuser** connection pool. Proves Layer 5 (data) of the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). Decision
record: [ADR-0002](../docs/adr/0002-tenant-isolation-rls-session-binding.md).

## How it works

1. Each tenant-scoped table has `ENABLE` + `FORCE ROW LEVEL SECURITY` and one
   policy keyed on a session GUC, for reads (`USING`) and writes (`WITH CHECK`):
   `tenant_id = current_setting('app.current_tenant')::uuid OR current_setting('app.bypass_rls') = 'on'`.
2. `tenant_id` **defaults from the session GUC**, so an insert is stamped with
   the active tenant — a caller cannot write a row for another tenant.
3. `TenantSessionDataSourceProxy` binds `app.current_tenant` (and `app.bypass_rls`
   for the system-ops tenant) on **every connection borrow** from `TenantContext`
   — transaction-local inside a transaction, session-scoped otherwise with a
   reset on connection return. Unbound borrow **fails closed**.
4. The runtime pool authenticates as a `NOSUPERUSER NOBYPASSRLS` role.

## The lesson: policy is not enough — the role is the crux

A PostgreSQL **superuser bypasses RLS unconditionally** — `FORCE`, the policy,
and the GUC are all ignored. Dev images commonly connect as the bootstrap
superuser, silently disabling isolation even with perfect DDL. The fix is
structural and lives in the *pool identity*: a dedicated `NOSUPERUSER
NOBYPASSRLS` role, with migrations run by a separate, more-privileged migrator.

`PoolIdentityAuditTest` makes "the pool is not a superuser" a build-breaking
invariant.

### A subtlety about testing that invariant

In production the guard is a **static audit of the datasource configuration**,
not an integration test: an integration test connects as the test database's
bootstrap superuser, so it would pass in CI while production stayed vulnerable.
This module additionally asserts a **live runtime audit** (`current_user` is
non-superuser, non-bypass) because here the pool is deliberately the
`tenant_user` role — so the live check is truthful. Use the static-config audit
when the test database's identity differs from production's.

## Run it

Requires JDK 21 and Docker.

```bash
../gradlew :tenant-isolation:test
```

Tests (Testcontainers, PostgreSQL 16):

- `RlsIsolationTest` — a tenant reads only its own rows; the session stamps
  `tenant_id` on insert; the system-ops tenant sees across tenants via
  `app.bypass_rls`; a cross-tenant write is rejected; an unbound borrow fails
  closed.
- `PoolIdentityAuditTest` — the runtime pool role is non-superuser, non-bypass.
