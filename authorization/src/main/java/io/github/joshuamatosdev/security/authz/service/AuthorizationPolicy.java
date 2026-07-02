package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.decision.*;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;

import java.util.Optional;

/**
 * The access decision, as a pure function of the actor, the resource, the action, and the tenant's
 * effective rules. No I/O, no thread-locals, no framework — every branch is unit-testable in
 * isolation. The variants are evaluated in a fixed order, and the function ends in a deny, so there
 * is no implicit permit:
 *
 * <ol>
 *   <li><b>Tenant membership</b> — a cross-tenant request is denied here and can be rescued by
 *       nothing below it.
 *   <li><b>Explicit deny</b> — a DENY rule for the action wins over any allow (deny-overrides).
 *   <li><b>Wide-scope admin</b> — a tenant-scoped admin grant short-circuits to allow (audited as
 *       wide-scope by the caller).
 *   <li><b>Resource grant</b> — the resource owner is allowed.
 *   <li><b>Team membership</b> — a team-scoped ALLOW rule matched in the resource's organization
 *       and team (the most specific rule scope).
 *   <li><b>Organization membership</b> — an organization-scoped ALLOW rule matched in the resource's
 *       organization.
 *   <li><b>Effective permission</b> — a tenant-scoped ALLOW rule matched a tenant-wide role.
 *   <li>otherwise — <b>deny by default</b>.
 * </ol>
 *
 * <p>Why this exists: the service layer is the single authorization decision point, preventing
 * callers from skipping audit or fine-grained resource checks.
 */
public final class AuthorizationPolicy {

    public Decision decide(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final EffectivePolicy effectivePolicy) {

        // 1. Tenant membership — the outer boundary.
        if (!actor.tenantId().equals(resource.tenantId())) {
            return new Deny(DenialReason.TENANT_MISMATCH);
        }

        // 2. Explicit deny — deny overrides every allow, including broad grants.
        if (effectivePolicy.denies(actor.roleAssignments(), resource.organizationId(), resource.teamId(), action)) {
            return new Deny(DenialReason.EXPLICIT_DENY);
        }

        // 3. Audited wide-scope admin short-circuit.
        if (actor.hasTenantScopedRole(Roles.PLATFORM_ADMIN)) {
            return new Allow(GrantBasis.WIDE_SCOPE_ADMIN);
        }

        // 4. Resource grant (ownership).
        if (resource.ownerPrincipalType() != null
            && resource.ownerPrincipalKey() != null
            && resource.ownerPrincipalType() == actor.principal().principalType()
            && resource.ownerPrincipalKey().equals(actor.principalKey())) {
            return new Allow(GrantBasis.RESOURCE_OWNER);
        }

        // 5/6/7. Effective ALLOW rule — most specific scope first: team, then organization, then
        // tenant-wide permission. The basis names the scope that actually granted.
        final Optional<PolicyScopeType> allowingScope = effectivePolicy.allowingScope(
            actor.roleAssignments(), resource.organizationId(), resource.teamId(), action);
        if (allowingScope.isPresent()) {
            return new Allow(switch (allowingScope.get()) {
                case TEAM -> GrantBasis.TEAM_MEMBER;
                case ORGANIZATION -> GrantBasis.ORGANIZATION_MEMBER;
                case TENANT -> GrantBasis.EFFECTIVE_PERMISSION;
            });
        }

        // 8. Deny by default.
        return new Deny(DenialReason.NO_MATCHING_RULE);
    }
}
