package io.github.joshuamatosdev.security.authz.request;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TeamId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * The facts about the <em>resource</em> a decision is made against: which tenant, organization, and
 * team it belongs to, and who owns it. These are resource-side facts the coarse edge gate cannot
 * know — they are exactly why a fine-grained, resource-aware decision is needed in addition to the
 * route gate.
 *
 * @param resourceId        the resource being acted on
 * @param tenantId          the tenant the resource belongs to
 * @param organizationId    the owning organization, if the resource is organization-scoped (may be {@code null})
 * @param teamId            the owning team within the organization, if the resource is team-placed
 *                          (may be {@code null}; requires {@code organizationId} — a team never
 *                          stands outside its organization)
 * @param ownerPrincipalType the {@link PolicyPrincipal#principalType()} of the owner, if any (may be {@code null})
 * @param ownerPrincipalKey the {@link PolicyPrincipal#principalKey()} of the owner, if any (may be {@code null})
 *
 * <p>Why this exists: request and resource facts are explicit policy inputs, which avoids
 * authorization decisions depending on mutable web framework state.
 */
public record ProtectedResource(
    ResourceId resourceId,
    TenantId tenantId,
    @Nullable OrganizationId organizationId,
    @Nullable TeamId teamId,
    @Nullable PrincipalType ownerPrincipalType,
    @Nullable String ownerPrincipalKey) {

    public ProtectedResource {
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (teamId != null && organizationId == null) {
            throw new IllegalArgumentException("a team-placed resource must also carry its organization");
        }
        if (ownerPrincipalKey != null) {
            RequiredText.require(ownerPrincipalKey, "ownerPrincipalKey");
        }
        if ((ownerPrincipalType == null) != (ownerPrincipalKey == null)) {
            throw new IllegalArgumentException(
                "ownerPrincipalType and ownerPrincipalKey must both be present or both be absent");
        }
    }

    /** The team-unplaced shape that predates the team dimension, kept for source compatibility. */
    public ProtectedResource(
        final ResourceId resourceId,
        final TenantId tenantId,
        @Nullable final OrganizationId organizationId,
        @Nullable final PrincipalType ownerPrincipalType,
        @Nullable final String ownerPrincipalKey) {
        this(resourceId, tenantId, organizationId, null, ownerPrincipalType, ownerPrincipalKey);
    }

    public ProtectedResource(
        final ResourceId resourceId,
        final TenantId tenantId,
        @Nullable final OrganizationId organizationId,
        @Nullable final String ownerPrincipalKey) {
        this(
            resourceId,
            tenantId,
            organizationId,
            null,
            ownerPrincipalKey == null ? null : PrincipalType.USER,
            ownerPrincipalKey);
    }
}
