package io.github.joshuamatosdev.security.tenant.binding;

/**
 * Observer extension point for {@link TenantSessionDataSourceProxy}. Production wiring would back this
 * with a metrics registry (counters for binding set, missing-tenant borrows, and failed resets);
 * this reference keeps the proxy dependency-free with a no-op default.
 *
 * <p>Why this exists: tenant binding is the handoff from request identity to database/session
 * controls and must be centralized rather than rebuilt ad hoc.
 */
public interface TenantBindingObserver {

    /**
     * Records that a tenant binding was applied to a borrowed connection.
     *
     * @param poolName logical pool name supplied by the datasource proxy
     */
    void onBindingSet(String poolName);

    /**
     * Records that a tenant-scoped pool was borrowed with no tenant in context.
     *
     * <p>The borrow fails closed after this callback; this signal is for metrics or alerts, not for
     * recovery.
     *
     * @param poolName logical pool name supplied by the datasource proxy
     */
    void onBindingMissing(String poolName);

    /**
     * Records that clearing the session binding on connection return failed.
     *
     * <p>The datasource proxy aborts the connection after this callback so an uncertain tenant claim
     * is not returned to the pool.
     *
     * @param poolName logical pool name supplied by the datasource proxy
     */
    void onResetFailed(String poolName);

    /**
     * Default observer used by the reference module when no metrics implementation is wired.
     */
    TenantBindingObserver NOOP = new TenantBindingObserver() {
        @Override
        public void onBindingSet(final String poolName) {}

        @Override
        public void onBindingMissing(final String poolName) {}

        @Override
        public void onResetFailed(final String poolName) {}
    };
}
