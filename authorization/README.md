# Authorization

A framework-free authorization decision core: scope-layered resource policy,
typed principals, immutable request context, deny-overrides, and an audit
record for every decision. The only runtime dependencies are `:shared` and
SLF4J — Spring, the web boundary, and persistence live in the demonstration
application, [`authorization-showcase`](../authorization-showcase/).

It covers Layer 2, authorization, in the
[five-layer posture](../docs/adr/0001-five-layer-security-posture.md). The
decision record is [ADR-0003](../docs/adr/0003-authorization.md).

## Table of Contents

- [Quick Start](#quick-start)
- [Library Artifacts](#library-artifacts)
- [What It Demonstrates](#what-it-demonstrates)
- [How Requests Are Authorized](#how-requests-are-authorized)
- [Decision Model](#decision-model)
- [Request Context](#request-context)
- [Audit](#audit)
- [The Showcase Application](#the-showcase-application)
- [Testing](#testing)

## Quick Start

Requirements:

- JDK 21

Run the module tests (pure, in-memory — no Docker):

```bash
../gradlew :authorization:test
```

## Library Artifacts

Plain Java or custom Spring wiring:

```kotlin
implementation("io.github.joshuamatosdev.security:authorization:0.1.0-SNAPSHOT")
testImplementation("io.github.joshuamatosdev.security:authorization-testkit:0.1.0-SNAPSHOT")
```

Spring Boot auto-configuration:

```kotlin
implementation("io.github.joshuamatosdev.security:authorization-spring-boot-starter:0.1.0-SNAPSHOT")
```

The starter wires the reference `AuthorizationService`, policy, in-memory rule
repository, and audit sink when `bulwark.authorization.enabled` is true or
absent; each bean backs off individually to an application-provided
replacement. In servlet web applications it also registers the 403 denial
advice that translates `AuthorizationDeniedException` into a response without
leaking decision internals. Disable everything with:

```yaml
bulwark:
  authorization:
    enabled: false
```

## What It Demonstrates

- Typed principals instead of bare strings.
- Immutable request context resolved once and passed as a value.
- Resource-aware policy for `CREATE`, `READ`, `UPDATE`, and `DELETE` (creation
  is decided against the prospective resource's placement).
- Tenant, organization, team, owner, and role-scope checks.
- Deny-overrides behavior.
- Audit records for every allow and deny.

## How Requests Are Authorized

The reference posture uses two gates:

1. **Coarse request gate.** A static URL-group to role table; a route matching
   no rule is denied. This gate is web-boundary code and is demonstrated in
   `authorization-showcase` (`web/gate/SecurityUrlGroup`, `web/gate/AccessRule`).
2. **Fine-grained policy.** This module.
   `service/AuthorizationService.enforce` evaluates the actor, resource,
   action, and effective policy. It writes an audit record before returning or
   throwing.

Boundary failures that occur before a resource policy can run still use
`AuthorizationService.deny` (or `denyWithoutTrustedContext` when no trusted
tenant context exists yet), so denials follow the same audit path.

## Decision Model

`AuthorizationPolicy.decide(actor, resource, action, effectivePolicy)` is a pure
function. It checks variants in order and ends in deny. There is no implicit
permit.

1. Tenant mismatch denies immediately.
2. Explicit `DENY` for the action wins over every allow.
3. Tenant-wide admin allows after deny checks.
4. Resource owner allows.
5. Team-scoped `ALLOW` allows within the resource's organization and team.
6. Organization-scoped `ALLOW` allows within the resource organization.
7. Tenant-scoped `ALLOW` allows through effective permissions.
8. No matching rule denies.

A role grant is action-specific and scope-specific. A grant to `READ` is not a
grant to `DELETE`, an organization-scoped grant is not tenant-wide access, and a
team-scoped grant is narrower still: it reaches only resources placed in its own
organization *and* team. Teams group people for grants — they are a
discretionary boundary in this layer, never a data-plane isolation dimension.

## Request Context

The actor is a sealed `principal/PolicyPrincipal`: either a `UserPrincipal` or a
`ServicePrincipal`. Per-request facts are resolved once into
`request/RequestContext` and passed as a value. Policy code does not read a
thread-local.

The context must be resolved from the authenticated principal alone — never
from request headers. The showcase demonstrates the pattern: its
`RequestContextResolver` builds the trusted profile from the `Authentication`,
and its `DocumentBoundaryAuthorizer` cross-checks the caller-supplied tenant
header against that resolved profile, denying a mismatch on the same audit
path. A header can neither manufacture nor revoke access; when no trusted
profile exists, audit keeps tenant context empty instead of copying an
untrusted header.

Typed identifiers come from `:shared`:

- `TenantId`
- `OrganizationId`
- `TeamId`
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

## The Showcase Application

`authorization-showcase` (not published) runs both gates in a real Spring web
application: the coarse route gate, the document API, demo identity resolution
gated behind `showcase.demo-identity` (default off), and PostgreSQL-backed
document facts whose primary keys are database-minted UUIDv7 values — matching
the `tenant-isolation` module's database-owned identifier contract.

Requirements: JDK 21 and Docker (PostgreSQL Testcontainers).

```bash
../gradlew :authorization-showcase:test
```

## Testing

Run all authorization tests:

```bash
../gradlew :authorization:test
```

Important tests:

- `AuthorizationPolicyTest`: each grant basis, deny reason, action boundary,
  organization boundary, and deny-overrides behavior.
- `DefaultAuthorizationServiceTest`: audit coverage for allows, denies,
  wide-scope admin decisions, and explicit boundary denials.
- `DocumentControllerSecurityTest` (in `authorization-showcase`): HTTP coverage
  for both gates, trusted header validation, deny-by-default routes, UUIDv7
  document id creation, persistence deletion, and 403 behavior for fine-grained
  denials.
