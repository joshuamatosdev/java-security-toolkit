package io.github.joshuamatosdev.security.tenant.binding;

/**
 * Observability seam for {@link TenantSessionDataSourceProxy}. Production wiring would back this
 * with a metrics registry (counters for binding set, missing-tenant borrows, and failed resets);
 * this reference keeps the proxy dependency-free with a no-op default.
 */
public interface TenantBindingObserver {

    /** A tenant binding was applied to a borrowed connection. */
    void onBindingSet(String poolName);

    /** A tenant-scoped pool was borrowed with no tenant in context (fail-closed). */
    void onBindingMissing(String poolName);

    /** Clearing the session binding on connection return failed; the connection was aborted. */
    void onResetFailed(String poolName);

    TenantBindingObserver NOOP = new TenantBindingObserver() {
        @Override
        public void onBindingSet(final String poolName) {}

        @Override
        public void onBindingMissing(final String poolName) {}

        @Override
        public void onResetFailed(final String poolName) {}
    };
}
