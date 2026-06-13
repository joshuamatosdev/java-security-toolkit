# Glossary

This glossary defines terms used across the security modules and ADRs. It favors
plain language over database or cloud shorthand.

## ADR

An Architecture Decision Record. An ADR records a design decision, the context
that made the decision necessary, alternatives that were rejected, and the
consequences of the chosen approach.

## BYPASSRLS

A PostgreSQL role attribute that lets a role ignore Row-Level Security policies.
A role with `BYPASSRLS` can see rows that RLS would normally hide, so tenant
runtime roles must not have it.

## Claim

A value that carries an asserted fact. In `tenant-isolation`, the claim says
which tenant is active for a database connection. The module signs the claim so
PostgreSQL can verify that it came from trusted application code and has not
expired.

## Connection Borrow

The moment application code asks the connection pool for a database connection.
`tenant-isolation` binds the signed tenant claim at borrow time because that is
when the application first receives a database session that can run SQL.

## Connection Pool

A reusable set of database connections. Creating a new database connection for
every request is expensive, so frameworks usually keep open connections and lend
them to application code as needed. Because pooled connections are reused, any
session state written to a connection must be cleared before the connection
returns to the pool.

## Custom Setting

A named PostgreSQL setting created by application code, such as
`app.tenant_claim`. PostgreSQL also calls these settings GUCs. Custom settings
are useful for passing request-local facts into database policies, but ordinary
SQL can change them unless the database verifies the value before trusting it.

## Database

The PostgreSQL server and schema that store application data. In prose, prefer
`database` over `DB` unless the surrounding code or configuration already uses
the abbreviation.

## Datasource

The Java object that hands out database connections. Spring applications usually
access the database through a `DataSource`. In `tenant-isolation`, the datasource
is wrapped so every borrowed connection receives the active tenant claim and is
reset on close.

## Fail-Closed

A security behavior where an error, missing context, or unverifiable state causes
the system to deny the operation. For example, if no tenant is bound when code
borrows a tenant-scoped connection, the module throws before SQL can run. The
opposite behavior, fail-open, would allow the operation when the guard cannot
prove it is safe.

## FORCE ROW LEVEL SECURITY

A PostgreSQL table setting that applies RLS policies even to the table owner. It
does not apply to PostgreSQL superusers, and it does not apply to roles with
`BYPASSRLS`.

## GUC

PostgreSQL shorthand for a configuration setting. The name comes from
"Grand Unified Configuration." In this module, `app.tenant_claim` is a custom
GUC stored on the database session.

## HMAC

Hash-based Message Authentication Code. It is a cryptographic signature created
with a shared secret. The Java code signs the tenant claim with an HMAC, and the
database verifies the HMAC before RLS trusts the claim.

## JDBC

Java Database Connectivity. JDBC is the standard Java API for database access.
Spring and Hibernate eventually use JDBC connections under the hood.

## PgBouncer

A PostgreSQL connection pooler that can sit between an application and the
database. PgBouncer has several pooling modes. Transaction-level pooling is not
compatible with this tenant binding because it does not keep one server
connection pinned to the application for the full session.

## RDS Proxy

An AWS managed database proxy for Amazon RDS and Aurora. Like any external
pooling layer, it must preserve the session state this module relies on. If it
does not pin session state to the same backend connection, it can break
session-bound tenant claims.

## RESTRICTIVE Policy

A Row-Level Security policy that a row must satisfy *in addition to* the ordinary
(permissive) policies, rather than as an alternative to them. Permissive policies
are OR-combined — passing any one grants access — while RESTRICTIVE policies are
AND-combined, so each one can only further narrow access. In `tenant-isolation`
the system-writer role is capped this way: it may hold `INSERT` and even a valid
tenant claim, but a RESTRICTIVE policy still pins its writes to the single
system-ops sentinel tenant.

## RLS

Row-Level Security. RLS is a PostgreSQL feature that applies a policy to each row
returned or written by SQL. In `tenant-isolation`, RLS compares each row's
`tenant_id` to the verified tenant claim stored on the database session.

## Session Binding

The act of writing request-local state to a database session before SQL runs.
Here, session binding means setting `app.tenant_claim` on the borrowed
PostgreSQL connection so RLS can evaluate the current tenant.

## Session-Level Pooling

A pooling mode where one client session stays attached to the same server
connection while session state matters. This is compatible with
`tenant-isolation` because the tenant claim remains on the connection that runs
the SQL.

## SQL Injection

A vulnerability where attacker-controlled input becomes executable SQL. This
module signs and verifies the tenant claim so injected SQL cannot simply set
`app.tenant_claim` to another tenant and pass RLS.

## System-Ops Pool

The separate read-only database pool used for operational cross-tenant reads. It
connects as `tenant_ops_user`, not as the ordinary tenant runtime role.

## tenant_bypass

The PostgreSQL role used as an explicit marker for read-only system-operations
access. Ordinary tenant traffic is not a member of this role.

## Tenant Context

The application-side value that says which tenant is active for the current
thread of work. `TenantContext` is useful for carrying the tenant to the
datasource wrapper, but the database still verifies the signed claim before RLS
trusts it.

## Transaction-Level Pooling

A pooling mode where a client can use one server connection for one transaction
and a different server connection for the next transaction. This is not
compatible with session-bound tenant claims because the claim may be written to
one connection while a later statement runs on another.

## UUIDv7

A time-ordered UUID format. The `tenant-isolation` demo lets PostgreSQL mint
UUIDv7 primary keys so the database, not the caller, owns record identity.
