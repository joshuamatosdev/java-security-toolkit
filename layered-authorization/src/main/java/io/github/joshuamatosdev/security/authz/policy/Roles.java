package io.github.joshuamatosdev.security.authz.policy;

/**
 * Neutral role keys used across the coarse request gate and the fine-grained policy. Two are enough
 * to show the pattern: a tenant-wide operator and an ordinary member. Role names are the value Spring
 * Security checks via {@code hasRole(...)} (without the {@code ROLE_} prefix it adds internally).
 */
public final class Roles {

    /**
     * Tenant-wide operator. A tenant-scoped {@code PLATFORM_ADMIN} assignment is the wide-scope admin short-circuit.
     */
    public static final String PLATFORM_ADMIN = "PLATFORM_ADMIN";

    /**
     * An ordinary member, typically assigned within one organization.
     */
    public static final String MEMBER = "MEMBER";

    private Roles() {
    }
}
