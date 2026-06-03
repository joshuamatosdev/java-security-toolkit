package io.github.joshuamatosdev.security.tenant.datasource.pool;


/**
 * Produces a stable read-only pool snapshot without exposing the underlying pool.
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


