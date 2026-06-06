package io.github.joshuamatosdev.security.tenant.datasource.factory;

import io.github.joshuamatosdev.security.tenant.datasource.session.TenantClaimSigner;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Creates tenant claim signers for database-enforced tenant checks.
 *
 * <p>Why this exists: factory-owned composition keeps placement mode, runtime credentials, and
 * signed-claim wiring in one auditable construction path.
 */
final class TenantClaimSignerFactory {

    /**
     * Tenant claim lifetime. The claim is re-minted on every connection borrow and verified per
     * statement, so it need only exceed the longest single borrow — kept short so a captured claim
     * has a narrow replay window. Two minutes is generous headroom over any realistic borrow while
     * being far tighter than the prior thirty.
     */
    private static final Duration CLAIM_TTL = Duration.ofSeconds(120);

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
        return new TenantClaimSigner(bindingProperties.requireClaimSecret(), CLAIM_TTL, clock);
    }
}
