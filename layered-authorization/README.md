# Layered Authorization

A runnable reference for deny-by-default authorization behind a coarse request
gate. The module keeps route-level protection, resource-level policy, trusted
request context, and audit records as separate responsibilities.

It covers Layer 2, authorization, in the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The
decision record is [ADR-0003](../docs/adr/0003-layered-authorization.md).

## Table of Contents

- [Quick Start](#quick-start)
- [What It Demonstrates](#what-it-demonstrates)
- [How Requests Are Authorized](#how-requests-are-authorized)
- [Decision Model](#decision-model)
- [Request Context](#request-context)
- [Audit](#audit)
- [Persistence](#persistence)
- [Testing](#testing)

## Quick Start

Requirements:

- JDK 21
- Docker, for PostgreSQL Testcontainers in the HTTP tests

Run the module tests:

```bash
../gradlew :layered-authorization:test
```

The pure policy tests run in memory. HTTP tests start PostgreSQL 18 so document
facts use database-owned UUIDv7 identifiers.

## What It Demonstrates

- Deny-by-default route protection.
- Typed principals instead of bare strings.
- Immutable request context resolved once at the web boundary.
- Resource-aware policy for `READ`, `UPDATE`, and `DELETE`. `UPDATE` is modeled
  in the policy layer; the HTTP surface exposes `READ` and `DELETE`.
- Tenant, organization, owner, and role-scope checks.
- Deny-overrides behavior.
- Audit records for every allow and deny.
- PostgreSQL-backed document facts with database-owned identifiers.

## How Requests Are Authorized

The module uses two gates:

1. **Coarse request gate.** `web/gate/SecurityUrlGroup` and
   `web/gate/AccessRule` define a static URL-group to role table in
   `web/config/SecurityConfig`. A route matching no rule is denied.
2. **Fine-grained policy.** `service/AuthorizationService.enforce` evaluates
   the actor, resource, action, and effective policy. It writes an audit record
   before returning or throwing.

Boundary failures that occur before a resource policy can run still use
`AuthorizationService.deny`, so denials follow the same audit path.

## Decision Model

`AuthorizationPolicy.decide(actor, resource, action, effectivePolicy)` is a pure
function. It checks variants in order and ends in deny. There is no implicit
permit.

1. Tenant mismatch denies immediately.
2. Explicit `DENY` for the action wins over every allow.
3. Tenant-wide admin allows after deny checks.
4. Resource owner allows.
5. Organization-scoped `ALLOW` allows within the resource organization.
6. Tenant-scoped `ALLOW` allows through effective permissions.
7. No matching rule denies.

A role grant is action-specific and scope-specific. A grant to `READ` is not a
grant to `DELETE`, and an organization-scoped grant is not tenant-wide access.

## Request Context

The actor is a sealed `principal/PolicyPrincipal`: either a `UserPrincipal` or a
`ServicePrincipal`. Per-request facts are resolved once into
`request/RequestContext` and passed as a value. Policy code does not read a
thread-local.

The trusted actor profile is resolved from the authenticated subject by
`web/RequestContextResolver` — not from request headers. Before a resource is
loaded, `web/DocumentBoundaryAuthorizer` cross-checks the caller-supplied tenant
header against the resolved profile and denies a mismatch on the same audit
path. The organization a caller may claim is not an authorization input:
organization membership comes from the trusted profile and the resource's own
organization, so a header can neither manufacture nor revoke access. If no
trusted profile exists, audit keeps tenant context empty instead of copying an
untrusted tenant header.

Typed identifiers come from `:shared`:

- `TenantId`
- `OrganizationId`
- `ResourceId`

## Audit

`DefaultAuthorizationService` writes an `AuthorizationAuditRecord` for every
decision:

- allow
- deny
- explicit boundary denial

The record includes principal, tenant, organization, resource, action, outcome,
grant basis or denial reason, wide-scope flag, and correlation id. Tenant can be
empty only when the denial happens before trusted actor tenant context exists.

## Persistence

Document resource facts are loaded from PostgreSQL, not from an in-memory map.
PostgreSQL 18 owns document primary-key creation through the `id_v7` domain
default (`uuidv7()`), matching the `tenant-isolation` module's database-owned
identifier contract.

Application code omits `id` on insert and reads back the database-minted UUIDv7
value.

## Testing

Run all layered-authorization tests:

```bash
../gradlew :layered-authorization:test
```

Important tests:

- `AuthorizationPolicyTest`: each grant basis, deny reason, action boundary,
  organization boundary, and deny-overrides behavior.
- `DefaultAuthorizationServiceTest`: audit coverage for allows, denies,
  wide-scope admin decisions, and explicit boundary denials.
- `DocumentControllerSecurityTest`: HTTP coverage for both gates, trusted header
  validation, deny-by-default routes, UUIDv7 document id creation, persistence
  deletion, and 403 behavior for fine-grained denials.
