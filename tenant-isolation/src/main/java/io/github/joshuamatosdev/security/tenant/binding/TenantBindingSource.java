package io.github.joshuamatosdev.security.tenant.binding;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.Optional;

/** Read-only source of the tenant binding active for the current execution. */
@FunctionalInterface
public interface TenantBindingSource {

    Optional<TenantBinding> currentBinding();

    default Optional<TenantId> current() {
        return currentBinding().map(TenantBinding::tenant);
    }

    default Optional<OrganizationId> currentOrganization() {
        return currentBinding().map(TenantBinding::organization);
    }

    default TenantId requireCurrent() {
        return current().orElseThrow(() -> new SecurityException(
                "TenantContext not populated — tenant-scoped operation attempted without tenant binding"));
    }

    default OrganizationId requireCurrentOrganization() {
        return currentOrganization().orElseThrow(() -> new SecurityException(
                "TenantContext organization not populated — organization-scoped operation attempted"
                        + " without organization binding"));
    }
}
