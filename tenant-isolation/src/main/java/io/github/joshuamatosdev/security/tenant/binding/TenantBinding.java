package io.github.joshuamatosdev.security.tenant.binding;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/** Immutable tenant and optional organization bound as one atomic value. */
@SystemTenantBoundary
public record TenantBinding(TenantId tenant, @Nullable OrganizationId organization) {

    public TenantBinding {
        Objects.requireNonNull(tenant, "tenant must not be null");
        if (TenantIds.SYSTEM_OPS.equals(tenant) && organization != null) {
            throw new IllegalArgumentException("SYSTEM_OPS binding must not carry an organization");
        }
    }

    public static TenantBinding tenant(final TenantId tenant) {
        return new TenantBinding(tenant, null);
    }

    public static TenantBinding tenantAndOrganization(
            final TenantId tenant, final OrganizationId organization) {
        return new TenantBinding(tenant, Objects.requireNonNull(organization, "organization must not be null"));
    }

    public static TenantBinding systemOps() {
        return new TenantBinding(TenantIds.SYSTEM_OPS, null);
    }

    public boolean isSystemOps() {
        return TenantIds.SYSTEM_OPS.equals(tenant);
    }
}
