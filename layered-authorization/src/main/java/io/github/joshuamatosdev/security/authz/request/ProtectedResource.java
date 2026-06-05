package io.github.joshuamatosdev.security.authz.request;

import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * The facts about the <em>resource</em> a decision is made against: which tenant and organization it
 * belongs to, and who owns it. These are resource-side facts the coarse edge gate cannot know — they
 * are exactly why a fine-grained, resource-aware decision is needed in addition to the route gate.
 *
 * @param resourceId        the resource being acted on
 * @param tenantId          the tenant the resource belongs to
 * @param organizationId    the owning organization, if the resource is organization-scoped (may be {@code null})
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
    @Nullable PrincipalType ownerPrincipalType,
    @Nullable String ownerPrincipalKey) {

    public ProtectedResource {
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        if (ownerPrincipalKey != null && ownerPrincipalKey.isBlank()) {
            throw new IllegalArgumentException("ownerPrincipalKey must not be blank");
        }
        if (ownerPrincipalKey != null && !ownerPrincipalKey.equals(ownerPrincipalKey.strip())) {
            throw new IllegalArgumentException("ownerPrincipalKey must not include leading or trailing whitespace");
        }
        if (ownerPrincipalKey != null && ownerPrincipalKey.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("ownerPrincipalKey must not contain control characters");
        }
        if ((ownerPrincipalType == null) != (ownerPrincipalKey == null)) {
            throw new IllegalArgumentException(
                "ownerPrincipalType and ownerPrincipalKey must both be present or both be absent");
        }
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
            ownerPrincipalKey == null ? null : PrincipalType.USER,
            ownerPrincipalKey);
    }
}
