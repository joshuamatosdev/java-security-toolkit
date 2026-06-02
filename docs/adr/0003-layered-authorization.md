# ADR-0003: Layered Authorization — Typed Principal, Scoped Per-Action Policy, Deny-by-Default

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

Authentication answers *who is calling*; authorization answers *may this caller
do this action on this resource*. The second question cannot be answered at one
place. A coarse edge gate knows the route and the caller's roles but not which
resource is being touched or who owns it. A fine-grained service decision knows
the resource but should not be re-checking whether the route was even allowed.

If authorization is left to convention — each handler remembering to check a role
— the failure mode is silent: one missing check is one privilege escalation.
Authorization must be **structural** (Layer 2 of [ADR-0001](0001-five-layer-security-posture.md)),
**deny-by-default**, and **audited** on every decision, grant or deny.

A second trap is the **untyped principal**. When the actor flows through the code
as a bare `String subject` or a `Map<String,Object> claims`, any string can be
mistaken for an actor, a service token and a human user are indistinguishable,
and the authorization version that should force a re-check on a permission change
is easy to drop. The actor must be a closed, typed set.

A third trap is **role-only** authorization (`hasRole("MEMBER")`) for
resource-scoped decisions. "A member" is not a fact about *this* resource. The
real question is "a member **of the organization that owns this resource**, with
an active rule permitting **this action**." Scope and action are part of the
decision, not an afterthought.

## Decision

### A typed, sealed principal

The actor is a sealed interface with exactly two implementations:

```java
public sealed interface PolicyPrincipal permits UserPrincipal, ServicePrincipal {
    PrincipalType principalType();
    String principalKey();          // subject for a user, clientId for a service
    long authorizationVersion();    // bumped to force re-evaluation after a grant change
}
```

A human is a `UserPrincipal` (subject + email); a machine caller is a
`ServicePrincipal` (clientId + kind). The compiler enforces that every decision
handles both — there is no third, untyped kind of actor.

### An immutable request context, resolved once, passed by parameter

Per-request facts (the principal, the verified tenant, the optional
organization, the actor's scoped role assignments, a correlation id) are resolved
**once** at the edge of the request into an immutable `RequestContext` and then
passed **by parameter** into the decision. Decisions never reach back into a
thread-local or re-parse a token. A decision is a pure function of its inputs.

### Two gates, one posture

1. **Coarse request gate (the edge of this service).** A static map of URL
   group → required role, applied deny-by-default: a route that matches no rule
   is `denyAll()`, not "permit". This is `SecurityUrlGroup` + `AccessRule`. It is
   cheap, it runs first, and it rejects whole classes of request before any
   domain code runs. It is **necessary but not sufficient** — it cannot see the
   resource.

2. **Fine-grained policy (the service).** For a decision about a specific
   resource, an `AuthorizationService.enforce(actor, resource, action)` evaluates
   the access variants below, records an audit entry, and throws on deny. This is
   where object-level access lives.

### The access variants — evaluated in order, deny-by-default

```
decide(actor, resource, action):
  1. Tenant membership   — actor.tenant != resource.tenant      → DENY (TENANT_MISMATCH)
  2. Wide-scope admin    — actor has a tenant-scoped admin grant → ALLOW (audited, short-circuit)
  3. Explicit deny       — any DENY rule matches (deny-overrides)→ DENY (EXPLICIT_DENY)
  4. Resource grant      — actor is the resource owner           → ALLOW (RESOURCE_OWNER)
  5. Organization member — an ORG-scoped ALLOW rule matches the
                           resource's org for this action        → ALLOW (ORGANIZATION_MEMBER)
  6. Effective permission— a TENANT-scoped ALLOW rule matches
                           this action                           → ALLOW (EFFECTIVE_PERMISSION)
  7. (no rule matched)                                           → DENY (NO_MATCHING_RULE)
```

Key properties:

- **Tenant is the outer boundary.** A cross-tenant request is denied before any
  other variant is considered — it can never be rescued by a role or an
  ownership claim.
- **Deny overrides allow.** An explicit `DENY` rule for the action wins over any
  `ALLOW`, so a revocation is effective immediately and cannot be out-voted by a
  broad grant.
- **Scope and action are first-class.** A rule is `(roleKey, action, effect,
  scope)`. An `ORGANIZATION`-scoped rule matches only when the actor holds that
  role **in the resource's organization**; a `TENANT`-scoped rule matches
  tenant-wide. The action (`READ` / `UPDATE` / `DELETE`) must match — a grant to
  read is not a grant to delete.
- **Wide-scope admin is a short-circuit, and it is audited as such.** The
  platform operator can act across the tenant, but every such decision is written
  to the audit trail flagged `wideScope`, so a broad capability is never silent.
- **No implicit permit.** The function ends in `DENY`. Adding a new action or a
  new role cannot accidentally open access; it has no rule until one is written.

### Every decision is audited

`enforce` writes an `AuthorizationAuditRecord` for the decision — **allow and
deny alike** — carrying principal, tenant, organization, resource, action, the
outcome, the grant basis or denial reason, and the correlation id, *before* it
throws on a deny. A denial that is not recorded did not happen, as far as an
investigation is concerned.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Edge gate only | The edge cannot see the resource; it cannot answer object-level access (ownership, org scope). |
| Service checks only | Re-derives route/role facts the edge already has; loses the cheap, early, whole-class rejection. |
| Untyped principal (`String`/`Map`) | Any string becomes an actor; user vs service is indistinguishable; the re-check version is easily dropped. |
| Role-only (`hasRole`) for resource decisions | "A member" is not a fact about *this* resource; ignores owning-org scope and per-action granularity. |
| Allow-overrides / first-match-allow | A broad grant can out-vote a revocation; deny must override for revocation to be effective. |
| Default-permit with explicit denies | One forgotten deny is one escalation; the default must be deny. |
| Audit only denials | Wide-scope admin allows are the highest-risk decisions; they must be recorded too. |

## Consequences

- A new protected resource follows one shape: resolve `RequestContext`, build the
  `ProtectedResource` facts, call `enforce`. The decision logic is not
  reimplemented per handler.
- The decision is a **pure function** (`actor × resource × action × rules →
  Decision`), so each variant — grant path, deny path, deny-overrides, default
  deny — is unit-testable without a database, a container, or a running server.
- Changing what a role may do is a **rule change**, not a code change: add or
  retire a `(role, action, effect, scope)` rule.
- The audit trail answers "who was allowed/denied to do what, where, and why"
  for every decision, keyed by correlation id.
