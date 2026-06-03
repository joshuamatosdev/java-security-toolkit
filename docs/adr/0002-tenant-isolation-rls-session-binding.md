# ADR-0002: Tenant Isolation with Row-Level Security and Session Binding

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

In a shared-schema multi-tenant database, every row carries a `tenant_id`. If
isolation depends on application code remembering to add `WHERE tenant_id = ?`,
a single missing predicate can leak across tenants. The same risk exists for any
path that bypasses the ORM, including native queries, raw JDBC, replication
slots, and `pg_dump`. The boundary must live where the data lives.

## Decision

Enforce tenant isolation in PostgreSQL with Row-Level Security, bound to a
per-connection signed tenant claim.

### Database

Every tenant-scoped table:

```sql
ALTER TABLE document
    ALTER COLUMN tenant_id SET DEFAULT tenant_security.current_tenant_id();
ALTER TABLE document ENABLE ROW LEVEL SECURITY;
ALTER TABLE document FORCE ROW LEVEL SECURITY;
CREATE POLICY p_tenant_isolation ON document
    FOR ALL TO public
    USING (
        pg_has_role(current_user, 'tenant_bypass', 'USAGE')
        OR tenant_id = tenant_security.current_tenant_id()
    )
    WITH CHECK (
        tenant_id = tenant_security.current_tenant_id()
    );
```

- `ENABLE` + `FORCE`: `FORCE` subjects even the table owner to the policy.
- `USING` filters reads; `WITH CHECK` (same expression) rejects cross-tenant
  **writes**, not just reads.
- The `tenant_id` column **defaults from the verified tenant claim**. Inserts are
  stamped with the active tenant, so the caller cannot forget to set it and
  cannot set someone else's tenant. The `WITH CHECK` clause rejects a mismatched
  explicit value.
- Cross-tenant system-operations reads are gated by database role membership
  (`tenant_bypass`), not by a caller-settable session variable. The ordinary
  runtime role is not a member of `tenant_bypass`.
- `app.tenant_claim` is treated as a mutable transport envelope, not an authority.
  The `tenant_security.current_tenant_id()` verifier accepts only
  `v2:<tenant_uuid>:<exp_epoch_seconds>:<hmac_sha256>` values signed with a
  DB-private secret over `v2:<tenant_uuid>:<exp_epoch_seconds>`. It verifies the
  HMAC and then the expiry, so a **captured claim cannot be replayed past its
  short lifetime** (the `exp` is inside the signed payload and cannot be extended
  without the secret). Ordinary tenant roles can execute the verifier but cannot
  read the secret.

### Application

A `DataSource` proxy signs and binds the tenant claim on **every connection
borrow** from the request-scoped tenant context:

- Bindings are session-scoped and the returned connection is wrapped so `close()`
  clears the claim before the connection returns to the pool.
- The claim carries a signed expiry (`exp`), minted `now + TTL` on every borrow.
  The TTL must exceed the longest single connection borrow because the claim is
  verified per statement and must stay valid for the whole borrow. A leaked claim
  is replayable only within its short window, not forever.
- The Java signer and DB verifier must be provisioned with the same secret.
  The showcase module uses a fictional local-only test secret; production uses
  secret management.
- **Fail-closed:** if a tenant-scoped pool is borrowed with no tenant in
  context, the borrow throws before any SQL can run.
- The system-operations tenant routes to a separate read-only pool whose login
  role is a member of `tenant_bypass`. Each pool carries its own credential. The
  system-ops pool takes a dedicated password in production so the two login roles
  never share a secret.

### Configurable placement modes

The module exposes the isolation topology as typed Spring configuration:

```yaml
tenant:
  isolation:
    mode: id       # id, schema, or database
```

`id` is the default and is the decision captured by this ADR: shared tables,
`tenant_id`, forced RLS, and the signed session claim described above.

`schema` mode keeps one database and resolves the active tenant to an allowlisted
schema from `tenant.isolation.schema.tenants`. The datasource selects that schema
on connection borrow and resets it before returning the connection to the pool.
Schema selection is placement, not a complete security boundary, when one
runtime role has privileges in multiple tenant schemas: ordinary SQL can
retarget `search_path` or qualify another schema name. Schema-mode tables
therefore keep a database-side tenant guard, such as forced signed-claim RLS, or
deployments must use per-schema runtime roles with privileges limited to exactly
one tenant schema. Schema creation, per-schema migrations, and schema-specific
privileges remain deployment provisioning work.

`database` mode resolves the active tenant to an allowlisted tenant database
placement from `tenant.isolation.database.tenants` and routes to that tenant's
JDBC pool. Migrations, backup, restore, pool sizing, and rollout sequencing are
per-tenant database concerns. Cross-tenant operational reads should iterate
explicit tenant placements or use a reporting store; a single ambient system-ops
connection is intentionally rejected.

In every mode, request input never constructs schema names, JDBC URLs, usernames,
or passwords. The request binds only a typed tenant identity; the datasource
resolves it through deployment-owned configuration.

### The role mesh and why it is the crux

`FORCE ROW LEVEL SECURITY` forces the table *owner* through the policy. It does
**not** force a **superuser**, and it does not force a role with `BYPASSRLS`. A
PostgreSQL superuser bypasses RLS unconditionally. `FORCE`, the policy, and the
claim do not apply to a superuser. Local/dev database images
commonly authenticate as the bootstrap superuser, which silently disables
isolation even with perfect DDL.

So the runtime database identity is structural, not incidental. This module's
shipped init SQL uses this role mesh:

| Tier | Attributes | Role |
|---|---|---|
| privilege holder | `NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT` | `tenant_app`, ordinary table privileges |
| runtime | `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT`, member of `tenant_app` | `tenant_user`, the connection pool |
| bypass marker | `NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT` | `tenant_bypass`, read-only cross-tenant policy marker |
| system ops | `LOGIN NOSUPERUSER NOBYPASSRLS INHERIT`, member of `tenant_bypass` | `tenant_ops_user`, read-only system-ops pool |

The connection pool connects as `tenant_user`. It is never a superuser, never
`BYPASSRLS`, and not a member of `tenant_bypass`. System-ops code connects as
`tenant_ops_user`, also never a superuser and never `BYPASSRLS`, but explicitly
in the read-only bypass marker role. This separation is what makes the policy
actually engage at runtime.

### Auditing the role attribute

This was a real finding: with correct DDL in place, isolation was silently
bypassed in a development environment because the pool connected as the bootstrap
superuser. The fix is structural (the pool identity), and it is guarded by a
test.

There is a subtlety in *how* you test it. An integration test that spins up a
throwaway PostgreSQL connects as that container's bootstrap superuser. In that
setup, an integration-time role check can **pass in CI even though production
remains vulnerable**. The production guard is therefore a **static audit of the datasource
configuration** that ships with the artifact: it fails if any pool is configured
with a known superuser/bypass identity, regardless of which database a test
happens to point at.

This showcase module additionally asserts a **live runtime audit** (the
connected `current_user` is `NOSUPERUSER NOBYPASSRLS`). This is meaningful here
because the demo deliberately wires the pool as the non-superuser `tenant_user`.
The two techniques are complementary; the module README explains when to use
which.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Convention-only `WHERE tenant_id = ?` | Cannot be enforced structurally; one missing predicate is one leak. Kept only as defense-in-depth restatement. |
| Directly trusting `current_setting('app.current_tenant')` | Custom GUCs are mutable by ordinary SQL; raw SQL or SQL injection running as `tenant_user` could retarget the session. Kept only as a legacy inert setting in tests. |
| Schema-per-tenant as the default | Operational work multiplies with each tenant at scale (migrations, pool sizing). RLS scales without schema multiplication. Schema mode is supported for deployments that accept those provisioning costs. |
| Database-per-tenant as the default | Stronger blast-radius isolation, but every tenant carries database provisioning, migrations, backup, restore, monitoring, and pool capacity. Database mode is supported when that operational model is required. |
| ORM-level filter (e.g. Hibernate `@Filter`) | Bypassed by native queries, raw JDBC, replication, and `pg_dump`. The database is the only complete boundary. |
| Correct policy, pool connects as superuser | Silently bypasses RLS. The policy becomes decorative. The role attribute is part of the control, not an ops detail. |

## Consequences

- A query without tenant scoping returns nothing rather than leaking. The failure
  mode is empty, not cross-tenant.
- Cross-tenant **writes** are rejected by the database, and the tenant column is
  stamped from the verified claim, so a forged `tenant_id` is impossible through
  the pool.
- A raw SQL path running as `tenant_user` can mutate custom GUCs, but a forged
  `app.tenant_claim` verifies to no tenant and therefore cannot read or write as
  another tenant. A *valid* claim is additionally bounded by its signed `exp`: a
  claim captured (e.g. from query-parameter logs) is replayable only until it
  expires, not indefinitely. The claim must still be protected as a secret. The
  lifetime limits the value of a leak, but it does not eliminate that value. Do
  not log the bind value.
- System-operations access is explicit, read-only, scoped to one well-known
  tenant, and gated by database role membership, not by an ambient USERSET GUC.
- The pool's non-superuser identity is a tested invariant, enforced by a static
  configuration audit (production) and a live runtime audit (this module).
- The system-operations tenant is reachable only through the explicit
  `runAsSystemOps`/`supplyAsSystemOps` entry points; the ordinary
  `runAs`/`supplyAs` setters reject it, so system-ops routing can never be
  activated through a request-style tenant setter (fail-closed).
- A tenant cannot be switched to a *different* tenant once a database transaction
  is active: the transaction may already have borrowed a tenant-bound connection,
  so the switch could not be honored at the database. The switch throws rather
  than silently running under the wrong tenant. Scoped tenant changes therefore
  cannot cross a DB transaction boundary.
- The configured placement mode is a startup topology choice. `schema` and
  `database` modes share the same fail-closed tenant context, but each requires
  matching provisioning and migration automation outside the runtime datasource.
  Schema mode also requires a database-side tenant guard on tenant schema tables
  unless each schema is reached only by a role whose privileges are limited to
  that schema.
- **Deployment constraint: session-level pooling only.** The binding is a
  session-scoped GUC, set at borrow and cleared at return on the same physical
  connection. A *transaction-level* external pooler (PgBouncer in transaction
  mode, RDS Proxy) does not pin a server connection across statements. That can
  break the binding because a statement may run on a connection that never
  received the claim, which fails closed. If the pooler does not reset session
  state, it can also leave a residual claim that crosses clients. Deploy behind
  direct connections or a session-level pooler. Do not put transaction-level
  pooling under this binding.
