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
 *   <li><b>Organization membership</b> — an organization-scoped ALLOW rule matched in the resource's
 *       organization.
 *   <li><b>Effective permission</b> — a tenant-scoped ALLOW rule matched a tenant-wide role.
 *   <li>otherwise — <b>deny by default</b>.
 * </ol>
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
        if (effectivePolicy.denies(actor.roleAssignments(), resource.organizationId(), action)) {
            return new Deny(DenialReason.EXPLICIT_DENY);
        }

        // 3. Audited wide-scope admin short-circuit.
        if (actor.hasTenantScopedRole(Roles.PLATFORM_ADMIN)) {
            return new Allow(GrantBasis.WIDE_SCOPE_ADMIN);
        }

        // 4. Resource grant (ownership).
        if (resource.ownerPrincipalKey() != null
            && resource.ownerPrincipalKey().equals(actor.principalKey())) {
            return new Allow(GrantBasis.RESOURCE_OWNER);
        }

        // 5/6. Effective ALLOW rule — organization membership (specific) before tenant-wide permission.
        final Optional<PolicyScopeType> allowingScope =
            effectivePolicy.allowingScope(actor.roleAssignments(), resource.organizationId(), action);
        if (allowingScope.isPresent()) {
            return new Allow(
                allowingScope.get() == PolicyScopeType.ORGANIZATION
                    ? GrantBasis.ORGANIZATION_MEMBER
                    : GrantBasis.EFFECTIVE_PERMISSION);
        }

        // 7. Deny by default.
        return new Deny(DenialReason.NO_MATCHING_RULE);
    }
}
