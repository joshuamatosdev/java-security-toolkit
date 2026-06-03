package io.github.joshuamatosdev.security.tenant.datasource.pool;

import java.util.List;

/**
 * Read-only pool inspection surface for tenant datasource infrastructure.
 *
 * <p>This interface exists so health and metrics code can observe pool state without unwrapping the
 * tenant-scoped {@link javax.sql.DataSource} to a raw vendor pool that can borrow unguarded
 * connections.
 */
public interface TenantPoolInspection {

    /**
     * Empty inspection surface used when no trusted infrastructure observer is wired.
     */
    TenantPoolInspection NONE = List::of;

    /**
     * Returns current snapshots for the pools behind the tenant datasource.
     *
     * @return immutable pool snapshots
     */
    List<TenantPoolSnapshot> snapshots();
}


