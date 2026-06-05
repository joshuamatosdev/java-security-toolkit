package io.github.joshuamatosdev.security.tenant.datasource.pool;


/**
 * Produces a stable read-only pool snapshot without exposing the underlying pool.
 *
 * <p>Why this exists: pool inspection makes runtime pool identity observable so tests can prove
 * least-privilege tenant connections are really in use.
 */
@FunctionalInterface
interface TenantPoolSnapshotSource {

    /**
     * Captures the current pool state.
     *
     * @return current read-only pool snapshot
     */
    TenantPoolSnapshot snapshot();
}


