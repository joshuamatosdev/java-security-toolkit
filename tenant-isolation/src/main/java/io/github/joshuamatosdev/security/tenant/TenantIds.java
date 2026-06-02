package io.github.joshuamatosdev.security.tenant;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;

/**
 * Well-known tenant identifiers.
 *
 * <p>{@code ACME} and {@code GLOBEX} are illustrative ordinary tenants. {@code SYSTEM_OPS} is the
 * single system-operations tenant: binding it sets {@code app.bypass_rls = on} so platform-level
 * observability and cross-tenant rollups can read across tenants. It is never an ordinary request
 * identity — {@link TenantContext} rejects it from the normal {@code runAs}/{@code supplyAs} paths.
 */
@SystemTenantBoundary
public final class TenantIds {

    public static final TenantId ACME = TenantId.fromString("0190a000-0000-7000-8000-0000000000a1");

    public static final TenantId GLOBEX = TenantId.fromString("0190a000-0000-7000-8000-0000000000b2");

    public static final TenantId SYSTEM_OPS = TenantId.fromString("0190a000-0000-7000-8000-0000000000c3");

    public static TenantId system() {
        return SYSTEM_OPS;
    }

    private TenantIds() {}
}
