# Glossary

This glossary defines shared terms across the modules. It favors plain language. Not database or cloud shorthand.

## BYPASSRLS

A PostgreSQL role attribute. It lets a role skip RLS. A `BYPASSRLS` role sees hidden rows. Tenant runtime roles must lack it.

## Claim

A value carrying an asserted fact. In `tenant-isolation`, it does one job. It names the tenant per connection. The module signs the claim. Then PostgreSQL verifies two things. It came from trusted application code. It has not expired.

## Connection Borrow

This is a moment in time. Application code asks the pool. It wants a database connection. `tenant-isolation` binds the signed claim then. Why then? The app first gets a session. That session can run SQL.

## Connection Pool

A reusable set of database connections. New connections are expensive to create. So frameworks keep connections open. They lend them out as needed. Pooled connections get reused. So clear any session state first. Do it before returning the connection.

## Custom Setting

A named PostgreSQL setting. Application code creates it. One example is `app.tenant_claim`. PostgreSQL also calls these settings GUCs. They pass request-local facts into policies. But ordinary SQL can change them. The database must verify it first.

## Database

The PostgreSQL server and schema. They store application data. In prose, prefer `database` over `DB`. Unless the surrounding code abbreviates it. Or the configuration does.

## Datasource

The Java object hands out connections. Spring apps use a `DataSource`. In `tenant-isolation`, the datasource is wrapped. Every borrowed connection gets the claim. It resets on close.

## Fail-Closed

A security behavior. It denies the operation on trouble. Trouble means an error. Or missing context. Or unverifiable state. Here is an example. No tenant is bound. Code borrows a tenant-scoped connection. The module throws before SQL runs. The opposite is fail-open. It allows unproven operations.

## FORCE ROW LEVEL SECURITY

A PostgreSQL table setting. It forces RLS on the owner. It skips PostgreSQL superusers. It skips `BYPASSRLS` roles.

## GUC

PostgreSQL shorthand for a configuration setting. The name means "Grand Unified Configuration." Here `app.tenant_claim` is a custom GUC. It lives on the database session.

## HMAC

Hash-based Message Authentication Code. It is a cryptographic signature. It uses a shared secret. The Java code signs the claim. It uses an HMAC. The database verifies the HMAC. Then RLS trusts the claim.

## JDBC

Java Database Connectivity. It is Java's standard database API. Spring and Hibernate use JDBC underneath.

## PgBouncer

A PostgreSQL connection pooler. It sits between app and database. PgBouncer has several pooling modes. Transaction-level pooling breaks this tenant binding. Why? It does not pin one connection. Not for the full session.

## RDS Proxy

An AWS managed database proxy. It serves Amazon RDS and Aurora. It is an external pooling layer. It must preserve the session state. This module relies on that state. It must pin session state correctly. Pin it to the same backend. Otherwise session-bound tenant claims break.

## RESTRICTIVE Policy

A strict kind of RLS policy. A row must satisfy it too. It adds to the permissive policies. Not an alternative to them. Permissive policies are OR-combined. Passing any one grants access. RESTRICTIVE policies are AND-combined. So each one only narrows access. Here it caps the system-writer role. That role may hold `INSERT`. It may hold a valid claim. A RESTRICTIVE policy pins those writes. They go to one sentinel tenant. That is the system-ops tenant.

## RLS

Row-Level Security. It is a PostgreSQL feature. It checks each row by policy. That covers rows read or written. Here RLS checks each row's `tenant_id`. It compares against the verified claim. The claim sits on the session.

## Session Binding

Writing request-local state to a session. It happens before SQL runs. Here it sets `app.tenant_claim`. On the borrowed PostgreSQL connection. Then RLS evaluates the current tenant.

## Session-Level Pooling

A pooling mode. One client session stays put. It keeps the same server connection. This holds while session state matters. It works with `tenant-isolation`. The tenant claim stays put. It stays on the SQL connection.

## SQL Injection

It is a vulnerability. Attacker input becomes executable SQL. This module signs the tenant claim. It also verifies the claim. So injected SQL cannot fake it. It cannot reset `app.tenant_claim` freely. So it cannot pass RLS.

## System-Ops Pool

A separate read-only database pool. It serves operational cross-tenant reads. It connects as `tenant_ops_user`. Not the ordinary tenant runtime role.

## tenant_bypass

A PostgreSQL role. It marks read-only system-operations access. The marker is explicit. Ordinary tenant traffic never joins it.

## Tenant Context

An application-side value. It names the active tenant. That is for the current thread. `TenantContext` carries the tenant along. It reaches the datasource wrapper. The database verifies the signed claim. This happens before RLS trusts it.

## Transaction-Level Pooling

A pooling mode. One transaction uses one server connection. The next uses a different one. This breaks session-bound tenant claims. Why? The claim sits on one connection. A later statement runs on another.

## UUIDv7

A time-ordered UUID format. The `tenant-isolation` demo uses it. PostgreSQL mints the UUIDv7 primary keys. So the database owns record identity. Not the caller.
