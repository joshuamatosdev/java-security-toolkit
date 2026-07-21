# Authorization

This is an authorization decision core. It is framework-free. It has scope-layered
resource policy. Principals are typed. Request context is immutable. It uses
deny-overrides. Every decision writes an audit record. Runtime needs just `:shared`
and SLF4J. Spring lives in the demo app. The web boundary lives there too.
Persistence lives there too. That app is
[`authorization-showcase`](../authorization-showcase/).

It covers Layer 2, authorization, in the repository's composed security posture.

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

These tests are pure and in-memory. No Docker is needed. Run the module tests:

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

The starter wires four reference beans. It wires the reference `AuthorizationService`.
It wires the policy. Its default rule repository denies all role-based permissions. It
wires the audit sink. This happens when `authorization.enabled` is true. It also applies
when absent. Each bean backs off individually. Your production `PolicyRuleRepository`
takes over. Servlet web apps also receive the 403 denial advice. The advice translates
`AuthorizationDeniedException`. It returns a response. It leaks no decision internals.
Disable everything with:

```yaml
authorization:
  enabled: false
```

The seeded in-memory policy exists only for local demonstrations. Opt in explicitly with
`authorization.demo-policy.enabled=true`; never use that switch in a deployment.

## What It Demonstrates

- Typed principals instead of bare strings.
- Immutable request context, resolved once. It is passed as a value.
- Resource-aware policy for four actions. These are `CREATE`, `READ`, `UPDATE`,
  `DELETE`. Creation checks the new resource's placement.
- Tenant, organization, team, owner, role-scope checks.
- Deny-overrides behavior.
- Audit records for allow and deny.

## How Requests Are Authorized

The reference posture uses two gates:

1. **Coarse request gate.** A static URL-group to role table. No matching rule means
   denied. This gate is web-boundary code. See `authorization-showcase`
   (`web/gate/SecurityUrlGroup`, `web/gate/AccessRule`).
2. **Fine-grained policy.** This module. `service/AuthorizationService.enforce`
   evaluates four things. These are actor, resource, and action. Also the effective
   policy. It writes an audit record first. Then it returns or throws.

Some boundary failures happen early. They run before any resource policy. These still
call `AuthorizationService.deny`. Without trusted tenant context, use
`denyWithoutTrustedContext`. All denials share one audit path.

## Decision Model

`AuthorizationPolicy.decide(actor, resource, action, effectivePolicy)` is a pure
function. It checks variants in order. It ends in deny. There is no implicit permit.

1. Tenant mismatch denies immediately.
2. Explicit `DENY` targets the action. It wins over every allow.
3. Tenant-wide admin allows after deny checks.
4. Resource owner allows.
5. Team-scoped `ALLOW` allows narrowly. It needs matching organization and team.
6. Organization-scoped `ALLOW` needs the resource's organization.
7. Tenant-scoped `ALLOW` allows through effective permissions.
8. No matching rule denies.

A role grant is action-specific. It is also scope-specific. A `READ` grant is not
`DELETE`. An organization grant is not tenant-wide. A team-scoped grant is narrower
still. It reaches one organization and team. Only its own. Teams group people for
grants. Here teams are a discretionary boundary. They never isolate the data plane.

## Request Context

The actor is a sealed `principal/PolicyPrincipal`. It is a `UserPrincipal` or
`ServicePrincipal`. Per-request facts resolve once. They become
`request/RequestContext`. It is passed as a value. Policy code reads no thread-local.

Resolve context from the authenticated principal. Never from request headers. The
showcase demonstrates this pattern. Its `RequestContextResolver` builds the trusted
profile. It reads from the `Authentication`. Its `DocumentBoundaryAuthorizer` runs
next. It checks the caller's tenant header. It compares against the resolved profile.
A mismatch is denied. The same audit path applies. A header cannot manufacture access.
It cannot revoke access either. Sometimes no trusted profile exists. Then audit keeps
tenant context empty. It never copies an untrusted header.

Typed identifiers come from `:shared`:

- `TenantId`
- `OrganizationId`
- `TeamId`
- `ResourceId`

## Audit

`DefaultAuthorizationService` writes an `AuthorizationAuditRecord`. It covers every
decision:

- allow
- deny
- explicit boundary denial

The record holds many fields. It has principal, tenant, and organization. It has
resource, action, and outcome. Grant basis or denial reason too. It has a wide-scope
flag. It has a correlation id. Tenant is empty in one case. Only before trusted actor
tenant context.

## The Showcase Application

`authorization-showcase` runs both gates. It is not published. It runs in Spring. A
real web application. It includes the coarse route gate. It includes the document API.
It includes demo identity resolution. This sits behind `showcase.demo-identity`. It
defaults off. It includes PostgreSQL-backed document facts. Their primary keys are
UUIDv7 values. The database mints them. This follows `tenant-isolation`'s
database-owned identifier contract.

Requirements: JDK 21 and Docker. It uses PostgreSQL Testcontainers.

```bash
../gradlew :authorization-showcase:test
```

## Testing

Run all authorization tests:

```bash
../gradlew :authorization:test
```

Important tests:

- `AuthorizationPolicyTest` covers each grant basis. It covers each deny reason. It
  covers action and organization boundaries. It covers deny-overrides behavior.
- `DefaultAuthorizationServiceTest` checks audit coverage. It covers allows and
  denies. It covers wide-scope admin decisions. It covers explicit boundary denials.
- `AccessRuleCoverageTest` lives in `authorization-showcase`. It scans every controller
  endpoint. Each must match a gate rule. An unmatched endpoint fails the build. So
  deny-by-default never hides a dead route.
- `DocumentControllerSecurityTest` lives in `authorization-showcase`. It covers both
  gates over HTTP. It checks trusted header validation. It checks deny-by-default
  routes. It checks UUIDv7 document id creation. It checks persistence deletion. It
  checks 403 for fine-grained denials.
