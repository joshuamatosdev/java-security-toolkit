package io.github.joshuamatosdev.security.authz.request;

import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
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
 * @param ownerPrincipalKey the {@link PolicyPrincipal#principalKey()} of the owner, if any (may be {@code null})
 */
public record ProtectedResource(
    ResourceId resourceId,
    TenantId tenantId,
    @Nullable OrganizationId organizationId,
    @Nullable String ownerPrincipalKey) {

    public ProtectedResource {
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
    }
}
