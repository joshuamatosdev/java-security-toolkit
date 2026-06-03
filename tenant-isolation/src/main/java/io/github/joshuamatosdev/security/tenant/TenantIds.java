package io.github.joshuamatosdev.security.tenant;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;

/**
 * Well-known tenant identifiers.
 *
 * <p>{@code ACME} and {@code GLOBEX} are illustrative ordinary tenants. {@code SYSTEM_OPS} is the
 * single system-operations tenant: binding it routes to the read-only system-ops pool so
 * platform-level observability and cross-tenant rollups can read across tenants. It is never an
 * ordinary request identity — {@link TenantContext} rejects it from the normal {@code runAs}/{@code
 * supplyAs} paths.
 */
@SystemTenantBoundary
public final class TenantIds {

    /**
     * Fictional ordinary tenant used by isolation tests and examples.
     */
    public static final TenantId ACME = TenantId.fromString("0190a000-0000-7000-8000-0000000000a1");

    /**
     * Fictional ordinary tenant used to prove cross-tenant reads and writes are blocked.
     */
    public static final TenantId GLOBEX = TenantId.fromString("0190a000-0000-7000-8000-0000000000b2");

    /**
     * Synthetic system-operations tenant that routes through the read-only bypass-role pool.
     *
     * <p>This identifier is not a request tenant. {@link TenantContext} allows it only through the
     * explicit system-ops entry points so ordinary request code cannot opt into cross-tenant reads.
     */
    public static final TenantId SYSTEM_OPS = TenantId.fromString("0190a000-0000-7000-8000-0000000000c3");

    /**
     * Returns the system-operations tenant identifier.
     *
     * @return the synthetic system-ops tenant
     */
    public static TenantId system() {
        return SYSTEM_OPS;
    }

    /**
     * Prevents construction of the constants' holder.
     */
    private TenantIds() {}
}
