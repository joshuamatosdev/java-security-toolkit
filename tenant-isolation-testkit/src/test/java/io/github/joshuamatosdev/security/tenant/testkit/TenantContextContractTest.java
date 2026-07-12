package io.github.joshuamatosdev.security.tenant.testkit;

import io.github.joshuamatosdev.security.tenant.binding.TenantContext;

class TenantContextContractTest implements TenantContextContract {

    private final TenantContext tenantContext = new TenantContext(() -> false);

    @Override
    public TenantContext tenantContext() {
        return tenantContext;
    }
}
