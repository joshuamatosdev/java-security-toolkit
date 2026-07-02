package io.github.joshuamatosdev.security.authz.audit;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.authz.decision.*;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One audit entry for one decision — written for allowing and denies alike. It answers, for an
 * investigation, "who was permitted or refused to do what, to which resource, where, when, and why".
 *
 * @param tenantId     set from trusted actor context; {@code null} when no trusted tenant context
 *                     exists yet
 * @param grantBasis   set when {@code allowed} is true (otherwise {@code null})
 * @param denialReason set when {@code allowed} is false (otherwise {@code null})
 * @param wideScope    true when the grant basis was the wide-scope admin short-circuit — the
 *                     highest-risk decision, flagged so it is never silent
 *
 * <p>Why this exists: audit types capture who did what, to which resource, where, when, and why so
 * authorization can be investigated after the request.
 */
public record AuthorizationAuditRecord(
    Instant at,
    UUID correlationId,
    PrincipalType principalType,
    String principalKey,
    @Nullable TenantId tenantId,
    ResourceId resourceId,
    @Nullable OrganizationId resourceOrganizationId,
    Action action,
    boolean allowed,
    @Nullable GrantBasis grantBasis,
    @Nullable DenialReason denialReason,
    boolean wideScope) {

    public AuthorizationAuditRecord {
        Objects.requireNonNull(at, "at must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(principalType, "principalType must not be null");
        requireText(principalKey);
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(action, "action must not be null");

        if (allowed) {
            Objects.requireNonNull(tenantId, "allowed audit records must include tenantId");
            Objects.requireNonNull(grantBasis, "allowed audit records must include grantBasis");
            if (denialReason != null) {
                throw new IllegalArgumentException("allowed audit records must not include denialReason");
            }
        } else {
            Objects.requireNonNull(denialReason, "denied audit records must include denialReason");
            if (grantBasis != null) {
                throw new IllegalArgumentException("denied audit records must not include grantBasis");
            }
        }
        if (wideScope != (grantBasis == GrantBasis.WIDE_SCOPE_ADMIN)) {
            throw new IllegalArgumentException("wideScope must match WIDE_SCOPE_ADMIN grant basis");
        }
    }

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

    public static AuthorizationAuditRecord boundaryDenyWithoutTrustedContext(
        final PolicyPrincipal principal,
        final UUID correlationId,
        final ProtectedResource resource,
        final Action action,
        final DenialReason reason,
        final Instant at) {

        return new AuthorizationAuditRecord(
            at,
            correlationId,
            principal.principalType(),
            principal.principalKey(),
            null,
            resource.resourceId(),
            resource.organizationId(),
            action,
            false,
            null,
            reason,
            false);
    }

    private static void requireText(final String value) {
        RequiredText.require(value, "principalKey");
    }
}
