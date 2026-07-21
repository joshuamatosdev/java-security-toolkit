package io.github.joshuamatosdev.security.tenant.datasource.factory;

import io.github.joshuamatosdev.security.tenant.datasource.session.TenantClaimSigner;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import java.time.Clock;
import java.util.Objects;

/**
 * Creates tenant claim signers for database-enforced tenant checks.
 *
 * <p>Why this exists: factory-owned composition keeps placement mode, runtime credentials, and
 * signed-claim wiring in one auditable construction path.
 */
final class TenantClaimSignerFactory {

    private final TenantBindingProperties bindingProperties;
    private final Clock clock;

    /**
     * Creates the signer factory.
     *
     * @param bindingProperties RLS session-claim settings
     * @param clock clock used to compute signed tenant claim expiry
     */
    TenantClaimSignerFactory(final TenantBindingProperties bindingProperties, final Clock clock) {
        this.bindingProperties = Objects.requireNonNull(bindingProperties, "bindingProperties");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Creates the signer used to mint signed PostgreSQL tenant claims.
     *
     * @return claim signer used by the tenant-aware datasource proxy
     */
    TenantClaimSigner tenantClaimSigner() {
        return new TenantClaimSigner(
                bindingProperties.requireClaimSecret(), bindingProperties.claimTtl(), clock);
    }
}
