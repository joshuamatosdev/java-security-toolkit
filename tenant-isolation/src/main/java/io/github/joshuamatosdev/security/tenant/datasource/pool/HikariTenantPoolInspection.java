package io.github.joshuamatosdev.security.tenant.datasource.pool;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@SystemTenantBoundary
public final class HikariTenantPoolInspection implements TenantPoolInspection {

    private final List<TenantPoolSnapshotSource> snapshotSources;

    /**
     * Creates a read-only view over one or more guarded tenant pools.
     *
     * <p>The varargs form covers the shared-database strategies where the datasource wiring owns a
     * small fixed set of pools, such as runtime plus system-ops for ID isolation, or one shared
     * runtime pool for schema isolation.
     *
     * @param pools raw tenant pools, retained only for metrics inspection
     */
    public HikariTenantPoolInspection(final HikariDataSource... pools) {
        this(List.of(pools));
    }

    /**
     * Creates a read-only view over the guarded tenant pools.
     *
     * <p>The collection form covers database-per-tenant routing, where the configured tenant
     * placement map creates a pool per tenant and the inspection surface reports all of them without
     * exposing the raw {@link HikariDataSource} instances to application code.
     *
     * @param pools raw tenant pools, retained only for metrics inspection
     */
    public HikariTenantPoolInspection(final Collection<HikariDataSource> pools) {
        this.snapshotSources = Objects.requireNonNull(pools, "pools").stream()
                .map(HikariTenantPoolInspection::snapshotSource)
                .toList();
    }

    /**
     * Captures the current state of each tenant pool without borrowing connections.
     *
     * @return immutable snapshots for the configured pools
     */
    @Override
    public List<TenantPoolSnapshot> snapshots() {
        return snapshotSources.stream().map(TenantPoolSnapshotSource::snapshot).toList();
    }

    private static TenantPoolSnapshotSource snapshotSource(final HikariDataSource pool) {
        return new HikariTenantPoolSnapshotSource(Objects.requireNonNull(pool, "pool"));
    }
}

