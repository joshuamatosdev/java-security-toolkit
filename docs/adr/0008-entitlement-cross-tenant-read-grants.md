# ADR-0008: Entitlement-Based Cross-Tenant Read Grants

- **Status:** Accepted
- **Date:** 2026-07-02

## Context

ADR-0002 makes the tenant boundary absolute for ordinary sessions, and ADR-0007
subdivides it. Neither answers a need real platforms have: deliberate,
platform-curated sharing across the tenant boundary — a marketplace dataset one
tenant licenses to another, a paid cross-region read, a Palantir-style commons
where the platform owner brokers who may see whose data.

Until now the only cross-tenant read paths were membership in the bypass role
(all tenants, all rows — an operational identity, not a sharing mechanism) or
weakening the application layer with special-case queries (the missing-predicate
failure mode again). There was no way to say, and prove at the database, "tenant
A may read tenant B's documents — read-only, revocable, and nothing else."

## Decision

Model the entitlement as data, enforce it as a second permissive read policy.

- **Grant ledger.** `tenant_security.read_grant` holds explicit rows:
  `(grantor_tenant_id, grantee_tenant_id, resource_class, expires_at)`. Grants
  are directional, class-scoped, optionally expiring, and unique per
  (grantor, grantee, class). Grant administration is a platform-plane write;
  ordinary tenant roles hold no privilege on the table at all.
- **Membership check.** `tenant_security.has_read_grant(owner_tenant, class)`
  is `SECURITY DEFINER`: it resolves the reader from the verified tenant claim
  and consults the ledger that the reader itself cannot select from. It returns
  false for own-tenant rows on purpose — an entitlement is never the reason a
  tenant sees its own data.
- **Policy.** `p_entitled_read` is `PERMISSIVE FOR SELECT`, OR-combined with
  the tenant policy: `USING (tenant_security.has_read_grant(tenant_id,
  'document'))`. Because no other command is covered, foreign rows remain
  invisible to every INSERT, UPDATE, and DELETE plan — read-only is structural,
  not conventional.
- **Organization interaction.** The RESTRICTIVE organization cap (ADR-0007)
  gains a tenant-mismatch escape in `USING`: the reader's own organization
  binding scopes its own tenant, never the grantor's rows (organization
  structure is an intra-tenant concept). The escape does not touch
  `WITH CHECK`, and every write still passes the tenant policy's own-tenant
  `WITH CHECK`, so it cannot widen writes.
- **No session-state change.** No new claim, no `TenantContext` change, no
  proxy change. Revocation is a row delete and takes effect on the next
  statement.

## Rationale

| Alternative | Reason rejected |
|---|---|
| Widen the tenant claim to carry a list of readable tenants | Couples sharing to claim TTL and re-issue (revocation lags until expiry), bloats a signed value that today names exactly one identity, and forces every verifier to migrate. |
| A bypass-style role per sharing pair | Role explosion, all-or-nothing visibility (no class scoping, no expiry), and grants stop being ordinary auditable rows. |
| Application-layer special-case queries | Re-introduces the missing-predicate failure mode ADR-0002 exists to remove; nothing at the database backs the boundary. |
| `FOR ALL` entitlement policy | An entitlement must never widen writes; `FOR SELECT` makes read-only structural instead of asking `WITH CHECK` to hold the line. |
| Tenant-writable grant table (self-service sharing) | Hostile SQL inside a tenant session could entitle itself to any tenant's data; grant administration must sit on the platform plane. |

## Consequences

- Sharing is executable and bounded: the reference tests prove the grant is
  directional, class-scoped, expiring, revocable, invisible to writes, and
  unforgeable/unenumerable from inside a tenant session — with no entitlement
  predicate anywhere in repository code.
- The grant graph is confidential. A tenant learns what an entitlement exposes
  only by reading rows, not who shares with whom.
- Granularity is the resource class (per-table). Row- or column-level sharing
  (markings) is a deliberate non-goal here; a design that needs it should add a
  dedicated marking dimension rather than overload the grant ledger.
- `has_read_grant` runs per row inside a `VOLATILE` policy call. The reference
  DDL favors legibility; a production adopter with large entitled scans can
  inline the `EXISTS` into the policy or materialize grantee lists, keeping the
  same contract the tests assert.
- `system_audit` deliberately has no entitlement policy: the platform ledger is
  not shareable tenant business data.
- The organization cap's tenant-mismatch escape changes no behavior absent
  grants (foreign rows were unreachable anyway) and keeps entitled reads usable
  for organization-bound sessions.
