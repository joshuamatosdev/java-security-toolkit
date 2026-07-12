package io.github.joshuamatosdev.security.authz.audit;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
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
 * @param outcome      sealed allow-or-deny outcome carrying exactly one rationale
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
    Decision outcome) {

    public AuthorizationAuditRecord {
        Objects.requireNonNull(at, "at must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(principalType, "principalType must not be null");
        requireText(principalKey);
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(outcome, "outcome must not be null");
        if (outcome instanceof Allow) {
            Objects.requireNonNull(tenantId, "allowed audit records must include tenantId");
        }
    }

    public static AuthorizationAuditRecord of(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final Decision decision,
        final Instant at) {

        return new AuthorizationAuditRecord(
            at,
            actor.correlationId(),
            actor.principal().principalType(),
            actor.principalKey(),
            actor.tenantId(),
            resource.resourceId(),
            resource.organizationId(),
            action,
            decision);
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
            new Deny(reason));
    }

    private static void requireText(final String value) {
        RequiredText.require(value, "principalKey");
    }
}
