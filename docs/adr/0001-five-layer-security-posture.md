# ADR-0001: Five-Layer Security Posture

- **Status:** Accepted
- **Date:** 2026-06-02

## Context

A multi-tenant platform handling sensitive records cannot treat security as a
feature or a later phase. Convention-based controls ("every developer remembers
to scope the query") fail silently: one missed predicate is one cross-tenant
leak. Security must be enforced structurally, at every layer, deny-by-default.

## Decision

Adopt a five-layer model. Each layer has a single responsibility and must not
drift into another's job. Every feature ships with authentication,
authorization, audit, and traceability in the same change — no partial security
implementation is admissible.

1. **Identity / Authentication.** OIDC provider; browser uses Authorization
   Code + PKCE; tokens carry coarse roles only — no fine-grained permissions in
   the token. MFA required for privileged roles; step-up for role elevation.
2. **Authorization.** Coarse route guards at the edge (deny-by-default; an
   unmatched path is 403). Fine-grained, resource-aware decisions in the
   service, behind a policy boundary. Never defer a 403 to a 404 to mask an
   authorization failure.
3. **Secrets / configuration.** No secret in git, no secret baked into an
   image. Rotation is a configuration change, not a code change. Example/config
   templates carry only non-sensitive placeholders.
4. **Transport / network / runtime isolation.** TLS in transit; egress-deny by
   default; least-privilege runtime (no privileged containers, minimal
   capabilities); security headers and a locked-down management surface.
5. **Data / supply chain.** One least-privilege database role per service;
   tenant isolation enforced in the database (see ADR-0002), not only in
   application predicates. SBOM on every build; signed artifacts; pinned base
   images; dependency scanning that blocks on high-severity findings.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Single-layer security (edge only) | Resource-scope decisions need domain knowledge the edge does not have; the edge cannot enforce object-level access. |
| Fine-grained permissions in the token | Token bloat; revocation requires re-issue; cache-coherence problems. |
| In-image secrets + tag-pinned base images | Secrets leak via registries; CVE response has no provenance. |
| Defer authorization to "phase 2" | Every change shipped without it becomes a backfill obligation. Security is structural, not phased. |

## Consequences

- Defense-in-depth: a failure in any one layer must not by itself cause
  exposure. Tenant isolation, for example, is enforced by the database **and**
  restated by typed application predicates.
- Every authorization decision (grant and deny) is logged with tenant,
  principal, and resource.
- Each module in this repo proves one layer concretely and runnably.
