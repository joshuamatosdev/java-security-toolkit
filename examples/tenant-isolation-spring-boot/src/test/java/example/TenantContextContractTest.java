package example;

import io.github.joshuamatosdev.security.tenant.testkit.TenantContextContract;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;

/**
 * Reuses the published testkit contract instead of copying the module's internal tests — the
 * adoption path the walkthrough describes for proving context binding in an adopter's own CI.
 */
class TenantContextContractTest implements TenantContextContract {
    private final TenantContext tenantContext = new TenantContext(() -> false);

    @Override
    public TenantContext tenantContext() {
        return tenantContext;
    }
}
