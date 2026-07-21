package io.github.joshuamatosdev.security.tenant.config;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.tenant.binding.OrganizationScope;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;

/**
 * Tenant session-claim settings shared by all isolation modes.
 *
 * <p>The signed claim is mandatory in every mode as a defense-in-depth control: ID isolation uses
 * it for RLS, while schema and database isolation use it so database defaults and constraints can
 * still verify which tenant the application intended to serve.
 *
 * <p>Why this exists: tenant placement is a security boundary, so validation rejects ambiguous or
 * unsafe configuration before any datasource can route traffic.
 *
 * @param claimSecret HMAC secret shared with the PostgreSQL verifier
 * @param systemOpsPassword password for the read-only system-ops pool
 * @param organizationScope how the datasource boundary treats the organization dimension: off
 *     (tenant-only, the default), optional (emit the signed organization claim when one is bound),
 *     or required (fail closed when an ordinary tenant borrow has no organization)
 * @param claimTtl lifetime of claims minted after a connection is acquired; configure this above
 *     the application's longest connection hold time
 */
@ConfigurationProperties("tenant.binding")
public record TenantBindingProperties(
        String claimSecret,
        String systemOpsPassword,
        OrganizationScope organizationScope,
        Duration claimTtl) {

    private static final Duration DEFAULT_CLAIM_TTL = Duration.ofSeconds(120);
    private static final Duration MINIMUM_CLAIM_TTL = Duration.ofSeconds(1);

    /**
     * Applies the tenant-only default for the organization dimension.
     */
    @ConstructorBinding
    public TenantBindingProperties {
        organizationScope = organizationScope == null ? OrganizationScope.OFF : organizationScope;
        claimTtl = claimTtl == null ? DEFAULT_CLAIM_TTL : claimTtl;
        if (claimTtl.compareTo(MINIMUM_CLAIM_TTL) < 0) {
            throw new IllegalArgumentException("tenant.binding.claim-ttl must be at least 1 second");
        }
    }

    /**
     * Creates binding settings with the default claim lifetime.
     *
     * @param claimSecret HMAC secret shared with the PostgreSQL verifier
     * @param systemOpsPassword password for the read-only system-ops pool
     * @param organizationScope organization binding posture
     */
    public TenantBindingProperties(
            final String claimSecret,
            final String systemOpsPassword,
            final OrganizationScope organizationScope) {
        this(claimSecret, systemOpsPassword, organizationScope, null);
    }

    /**
     * Creates tenant-only binding settings.
     *
     * @param claimSecret HMAC secret shared with the PostgreSQL verifier
     * @param systemOpsPassword password for the read-only system-ops pool
     */
    public TenantBindingProperties(final String claimSecret, final String systemOpsPassword) {
        this(claimSecret, systemOpsPassword, null, null);
    }

    /**
     * Returns the required tenant claim secret.
     *
     * @return populated claim secret
     */
    public String requireClaimSecret() {
        return requireNonBlank(
                claimSecret,
                "tenant.binding.claim-secret",
                "tenant.binding.claim-secret is required for tenant session binding");
    }

    /**
     * Returns the required system-ops password or fails startup for ID isolation.
     *
     * @return populated system-ops password
     */
    public String requireSystemOpsPasswordForIdMode() {
        return requireNonBlank(
                systemOpsPassword,
                "tenant.binding.system-ops-password",
                "tenant.binding.system-ops-password is required when tenant.isolation.mode=id");
    }

    /**
     * Returns the configured system-ops password or an empty value when the ID-only pool is unused.
     *
     * @return configured password or an empty string
     */
    public String systemOpsPasswordOrEmpty() {
        return systemOpsPassword == null ? "" : systemOpsPassword;
    }

    private static String requireNonBlank(
            final String value, final String property, final String missingMessage) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(missingMessage);
        }
        RequiredText.violation(value).ifPresent(violation -> {
            throw new IllegalStateException(property + " " + violation);
        });
        return value;
    }
}
