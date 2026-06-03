package io.github.joshuamatosdev.security.tenant.testfixtures;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;

import java.util.function.Supplier;

/**
 * Scopes a {@link TenantId} into {@link TenantContext} for the duration of a unit of work, then
 * restores the prior binding. Mirrors the production test fixture.
 */
public final class WithTenant {

    private WithTenant() {}

    public static void runAs(final TenantId tenant, final Runnable work) {
        TenantContext.runAs(tenant, work);
    }

    public static <T> T supplyAs(final TenantId tenant, final Supplier<T> work) {
        return TenantContext.supplyAs(tenant, work);
    }
}
