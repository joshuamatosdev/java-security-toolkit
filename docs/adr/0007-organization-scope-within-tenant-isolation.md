# ADR-0007: Organization Scope Within Tenant Isolation

- **Status:** Accepted, amended by
  [ADR-0008](0008-entitlement-cross-tenant-read-grants.md)
- **Date:** 2026-07-02

## Context

Multi-tenant SaaS systems routinely subdivide a tenant into organizations —
teams, departments, workspaces — and the authorization layer already treats the
organization as an identity dimension: `layered-authorization` resolves
organization-scoped role assignments and its policy contract asserts
organization-scope isolation. The data plane had no such dimension. Within a
tenant, every query saw the whole tenant, so any organization boundary existed
only as a query predicate convention — exactly the failure mode ADR-0002
removed for tenants: one missing `WHERE organization_id = ?` and an
organization boundary silently disappears, with no database control behind it.

The organization is not a second tenant. The tenant remains the outer isolation
boundary (placement, pool identity, RLS); the organization scopes rows within
it. A design that let the two dimensions bind or drift independently would
create skew: SQL running under tenant A with a stale organization from tenant B.

## Decision

Make the organization a co-equal dimension of the tenant binding, enforced at
the same connection boundary with a second signed claim.

- **Binding.** `TenantContext` holds one atomic binding `(tenant,
  organization?)`. The organization is bound only through the two-argument
  `runAs`/`supplyAs` entry points — there is no way to bind an organization
  without its tenant, and the tenant-before-transaction guard rejects an
  organization switch (including an unbind) once a tenant transaction is
  active. The system-operations tenant never carries an organization.
- **Claim.** On borrow, the datasource proxy signs and binds `app.org_claim` in
  the same format as the tenant claim but with its own version marker inside
  the signed payload (`v2o:<organization_uuid>:<exp>:<hmac>`). The kind marker
  means a captured tenant claim replayed into `app.org_claim` (or the reverse)
  fails verification even though both claims share one secret.
- **Database.** `tenant_security.current_org_id()` verifies the claim (same
  double-HMAC comparison and wall-clock expiry as the tenant verifier) and a
  `RESTRICTIVE` policy is AND-combined with the permissive tenant policy:
  an organization-bound session sees and writes only its organization's rows;
  an organization-unscoped session keeps whole-tenant visibility; rows with no
  organization stay visible only to organization-unscoped sessions and bypass
  readers. `organization_id` is stamped by column default from the verified
  claim, like `tenant_id`.
- **Posture.** `tenant.binding.organization-scope` selects `off` (default,
  tenant-only), `optional` (emit the claim when bound — the migration
  posture), or `required` (an ordinary tenant borrow without an organization
  fails closed before a connection is taken; system-ops is exempt).

## Rationale

| Alternative | Reason rejected |
|---|---|
| Separate organization context holder | Tenant and organization could bind, restore, or clear independently — skew between the two dimensions is exactly the failure this design must exclude. |
| Organization inside the tenant claim (one combined claim) | Changes the deployed `v2` claim contract, forcing every verifier and adopter to migrate at once; a second claim is append-only. |
| Application-layer organization filters only | Re-introduces the missing-predicate failure mode for organizations that ADR-0002 removed for tenants; nothing at the database backs the boundary. |
| Same version marker for both claim kinds | A valid tenant claim could satisfy the organization verifier (and vice versa) within its TTL — a claim-swap widening attack for anyone who can set a session variable. |
| `required` as the default | Breaks every tenant-only adopter on upgrade and removes the migration path; posture must be an explicit, auditable choice. |

## Consequences

- Organization enforcement is executable: the reference tests prove
  organization-bound reads, cross-organization write rejection, claim-kind
  separation, and stamping under real PostgreSQL, with no organization
  predicate anywhere in repository code.
- Adoption is incremental: `off` → `optional` (claims flow, policies can be
  introduced) → `required` (deny-if-absent), with no change to tenant-only
  behavior until a posture is chosen.
- An organization-unscoped session sees the whole tenant **by design**:
  organization scope subdivides a tenant; it never replaces tenant isolation.
  Consequently the residual risk of hostile SQL inside a borrowed connection is
  bounded to widening organization scope to its own tenant (by clearing or
  corrupting `app.org_claim`); it can never cross the tenant boundary, which
  the tenant claim and pool identity still hold.
- Rows without an organization are tenant-admin material. Backfills that assign
  them must run organization-unscoped.
- The organization claim binds in every isolation mode; the ID-mode reference
  DDL demonstrates the verifier and the RESTRICTIVE policy. Schema- and
  database-mode DDL can adopt the same pattern where organization boundaries
  matter inside those placements.

## Amendment (ADR-0008)

ADR-0008 adds a tenant-mismatch escape to the RESTRICTIVE cap's `USING` clause:
the cap scopes only the session's **own** tenant, so a foreign-tenant row —
reachable at all only through bypass membership or an explicit read
entitlement — is not filtered by the reader's own organization binding. The
organization dimension is an intra-tenant concept. `WITH CHECK` is unchanged,
and every write still passes the tenant policy's own-tenant `WITH CHECK`, so
the escape cannot widen writes. Within the session's own tenant, the behavior
specified above is unchanged.
