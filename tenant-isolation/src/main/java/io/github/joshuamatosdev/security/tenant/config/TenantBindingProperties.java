package io.github.joshuamatosdev.security.tenant.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tenant session-claim settings shared by all isolation modes.
 *
 * <p>The signed claim is mandatory in every mode as a defense-in-depth control: ID isolation uses
 * it for RLS, while schema and database isolation use it so database defaults and constraints can
 * still verify which tenant the application intended to serve.
 *
 * @param claimSecret HMAC secret shared with the PostgreSQL verifier
 * @param systemOpsPassword password for the read-only system-ops pool
 */
@ConfigurationProperties("tenant.binding")
public record TenantBindingProperties(String claimSecret, String systemOpsPassword) {

    /**
     * Returns the required tenant claim secret.
     *
     * @return populated claim secret
     */
    public String requireClaimSecret() {
        return requireNonBlank(claimSecret, "tenant.binding.claim-secret is required for tenant session binding");
    }

    /**
     * Returns the required system-ops password or fails startup for ID isolation.
     *
     * @return populated system-ops password
     */
    public String requireSystemOpsPasswordForIdMode() {
        return requireNonBlank(
                systemOpsPassword,
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

    private static String requireNonBlank(final String value, final String message) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(message);
        }
        return value;
    }
}
