# layered-authorization

Fine-grained, resource-aware authorization behind a coarse request gate — Layer 2
of the [five-layer posture](../docs/adr/0001-five-layer-security-posture.md),
deny-by-default and audited. Decision record:
[ADR-0003](../docs/adr/0003-layered-authorization.md).

## The two gates

1. **Coarse request gate** (`web/gate/SecurityUrlGroup` + `web/gate/AccessRule`,
   wired in `web/config/SecurityConfig`). A static URL-group → role table applied
   deny-by-default: a route matching no rule is `denyAll()`. Cheap, runs first,
   rejects whole classes of request — but it cannot see the resource.
2. **Fine-grained policy** (`service/AuthorizationService.enforce`). For a
   decision about a specific resource it evaluates the access variants, writes an
   audit entry, and throws on a deny. This is where object-level access lives.

## The decision (pure function, deny-by-default)

`service/AuthorizationPolicy.decide(actor, resource, action, effectivePolicy)`
walks the variants in order and ends in a deny — there is no implicit permit:

1. **Tenant membership** — actor's tenant ≠ resource's tenant → deny
   (`TENANT_MISMATCH`). The outer boundary; nothing below can rescue it.
2. **Wide-scope admin** — a tenant-scoped admin grant → allow, **audited** as
   wide-scope (a short-circuit; the highest-risk decision is never silent).
3. **Explicit deny** — a `DENY` rule for the action wins over any allow
   (deny-overrides), so a revocation is effective immediately.
4. **Resource grant** — the resource owner is allowed.
5. **Organization membership** — an organization-scoped `ALLOW` rule matched in
   the resource's organization (the team/org variant).
6. **Effective permission** — a tenant-scoped `ALLOW` rule matched a tenant-wide
   role.
7. otherwise → deny (`NO_MATCHING_RULE`).

## Scope and action are first-class

A rule is `(roleKey, action, effect, scope)`. The same role grants different
access depending on whether it is held **tenant-wide** or only **inside the
owning organization**, and **per action** — a grant to `READ` is not a grant to
`DELETE`. The seeded example policy lets an organization member `READ`/`UPDATE`
in-org and read tenant-wide, but only the owner or a wide-scope admin may
`DELETE`. Changing what a role may do is a rule change (data), not code.

## Typed principal, immutable context

The actor is a sealed `principal/PolicyPrincipal` (a `UserPrincipal` or a
`ServicePrincipal`) — never a bare string. Per-request facts are resolved once
into an immutable `request/RequestContext` and passed by parameter; decisions
never reach into a thread-local. Typed identifiers (`TenantId`,
`OrganizationId`, `ResourceId`) come from the shared `:shared` module.

## Audit

`service/DefaultAuthorizationService` writes an `audit/AuthorizationAuditRecord`
for **every** decision — allow and deny alike — before it throws on a deny. The
record carries principal, tenant, organization, resource, action, the outcome,
the grant basis or denial reason, the wide-scope flag, and a correlation id.

## Run it

Requires JDK 21 (no database — the decision is a pure in-memory function and the
policy rules come from an in-memory repository).

```bash
../gradlew :layered-authorization:test
```

Tests:

- `AuthorizationPolicyTest` — each access variant in isolation: every grant
  basis, the tenant-mismatch and default-deny denials, per-action granularity,
  organization-scope boundaries, and deny-overrides.
- `DefaultAuthorizationServiceTest` — every decision is audited; a deny is
  recorded before the guard throws; a wide-scope admin allow is flagged.
- `DocumentControllerSecurityTest` — both gates over HTTP: unauthenticated
  rejected, deny-by-default on an unmatched route, owner/admin allowed, and a
  fine-grained denial surfaced as 403.
