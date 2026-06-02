package io.github.joshuamatosdev.security.tenant.testfixtures;

import io.github.joshuamatosdev.security.tenant.TenantContext;
import io.github.joshuamatosdev.security.tenant.TenantId;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;

/**
 * Scopes a {@link TenantId} into {@link TenantContext} for the duration of a unit of work, then
 * restores the prior binding. Mirrors the production test fixture.
 */
public final class WithTenant {

    private WithTenant() {}

    public static void runAs(final TenantId tenant, final Runnable work) {
        final @Nullable TenantId prior = TenantContext.current().orElse(null);
        TenantContext.set(tenant);
        try {
            work.run();
        } finally {
            restore(prior);
        }
    }

    public static <T> T supplyAs(final TenantId tenant, final Supplier<T> work) {
        final @Nullable TenantId prior = TenantContext.current().orElse(null);
        TenantContext.set(tenant);
        try {
            return work.get();
        } finally {
            restore(prior);
        }
    }

    private static void restore(final @Nullable TenantId prior) {
        if (prior == null) {
            TenantContext.clear();
        } else {
            TenantContext.set(prior);
        }
    }
}
