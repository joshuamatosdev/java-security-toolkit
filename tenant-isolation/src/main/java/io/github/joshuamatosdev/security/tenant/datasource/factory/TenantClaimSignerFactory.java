package io.github.joshuamatosdev.security.tenant.datasource.factory;

import io.github.joshuamatosdev.security.tenant.datasource.session.TenantClaimSigner;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Creates tenant claim signers for database-enforced tenant checks.
 */
final class TenantClaimSignerFactory {

    /**
     * Tenant claim lifetime. The claim is re-minted on every connection borrow and verified per
     * statement, so this must exceed the longest single borrow.
     */
    private static final Duration CLAIM_TTL = Duration.ofMinutes(30);

    private final TenantBindingProperties bindingProperties;

    /**
     * Creates the signer factory.
     *
     * @param bindingProperties RLS session-claim settings
     */
    TenantClaimSignerFactory(final TenantBindingProperties bindingProperties) {
        this.bindingProperties = Objects.requireNonNull(bindingProperties, "bindingProperties");
    }

    /**
     * Creates the signer used to mint signed PostgreSQL tenant claims.
     *
     * @return claim signer used by the tenant-aware datasource proxy
     */
    TenantClaimSigner tenantClaimSigner() {
        return new TenantClaimSigner(bindingProperties.requireClaimSecret(), CLAIM_TTL, Clock.systemUTC());
    }
}

