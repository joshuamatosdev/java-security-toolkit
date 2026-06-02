package io.github.joshuamatosdev.security.authz.audit;

import io.github.joshuamatosdev.security.authz.decision.*;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.UUID;

/**
 * One audit entry for one decision — written for allowing and denies alike. It answers, for an
 * investigation, "who was permitted or refused to do what, to which resource, where, when, and why".
 *
 * @param grantBasis   set when {@code allowed} is true (otherwise {@code null})
 * @param denialReason set when {@code allowed} is false (otherwise {@code null})
 * @param wideScope    true when the grant basis was the wide-scope admin short-circuit — the
 *                     highest-risk decision, flagged so it is never silent
 */
public record AuthorizationAuditRecord(
    Instant at,
    UUID correlationId,
    PrincipalType principalType,
    String principalKey,
    TenantId tenantId,
    ResourceId resourceId,
    @Nullable OrganizationId resourceOrganizationId,
    Action action,
    boolean allowed,
    @Nullable GrantBasis grantBasis,
    @Nullable DenialReason denialReason,
    boolean wideScope) {

    public static AuthorizationAuditRecord of(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final Decision decision,
        final Instant at) {

        final boolean allowed = decision.allowed();
        final GrantBasis basis = decision instanceof Allow(GrantBasis basis1) ? basis1 : null;
        final DenialReason reason = decision instanceof Deny(DenialReason reason1) ? reason1 : null;
        return new AuthorizationAuditRecord(
            at,
            actor.correlationId(),
            actor.principal().principalType(),
            actor.principalKey(),
            actor.tenantId(),
            resource.resourceId(),
            resource.organizationId(),
            action,
            allowed,
            basis,
            reason,
            basis == GrantBasis.WIDE_SCOPE_ADMIN);
    }
}
