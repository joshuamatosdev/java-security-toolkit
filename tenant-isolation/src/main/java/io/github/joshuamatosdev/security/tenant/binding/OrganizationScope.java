package io.github.joshuamatosdev.security.tenant.binding;

/**
 * How the datasource boundary treats the organization dimension of a tenant binding.
 *
 * <p>Organizations subdivide a tenant: the tenant stays the outer isolation boundary, and an
 * organization scopes rows within it. The scope is configured with
 * {@code tenant.binding.organization-scope} and consumed by the tenant-aware datasource proxy on
 * every connection borrow.
 *
 * <p>The intended adoption path is {@link #OFF} → {@link #OPTIONAL} → {@link #REQUIRED}: start
 * tenant-only, then emit organization claims while data and policies migrate, then deny
 * organization-less borrows once every caller binds one.
 *
 * <p>Why this exists: organization scope is a security posture decision, so it must be an explicit,
 * auditable configuration value rather than an implicit side effect of whether a caller happened to
 * bind an organization.
 */
public enum OrganizationScope {

    /**
     * Tenant-only binding. No organization claim is emitted even when a caller binds an
     * organization. This is the default and matches tenant-only deployments.
     */
    OFF,

    /**
     * Emit the signed organization claim when the current binding carries an organization; borrows
     * without one stay permitted. This is the migration posture: organization-aware row policies can
     * be introduced while organization-less callers still work.
     */
    OPTIONAL,

    /**
     * Fail closed: an ordinary tenant borrow without a bound organization is rejected before a
     * connection is taken from the pool. The system-operations tenant is exempt because cross-tenant
     * operational work carries no organization.
     */
    REQUIRED
}
