package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.sql.Connection;
import java.sql.ConnectionBuilder;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.ShardingKeyBuilder;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Tenant-aware datasource for database-per-tenant deployments.
 *
 * <p>The active {@link TenantContext} is resolved against an allowlisted tenant-to-datasource map.
 * The selected tenant pool is the primary isolation boundary. {@code TenantDataSourceFactory} wraps
 * this router in {@link TenantSessionDataSourceProxy} so each selected database also receives the
 * signed tenant claim used by database defaults, checks, or RLS policies.
 *
 * <p>Why this exists: tenant placement routing is the boundary that chooses the physical schema or
 * database, so it must be explicit and auditable.
 */
@SystemTenantBoundary
public final class TenantDatabaseRoutingDataSource extends AbstractDataSource implements TenantPoolInspection, AutoCloseable {

    private final Map<TenantId, DataSource> dataSourceByTenant;
    private final TenantPoolInspection poolInspection;

    public TenantDatabaseRoutingDataSource(
            final Map<TenantId, ? extends DataSource> dataSourceByTenant,
            final TenantPoolInspection poolInspection) {
        this.dataSourceByTenant = validateDatabasePlacements(dataSourceByTenant);
        this.poolInspection = Objects.requireNonNull(poolInspection, "poolInspection");
    }

    @Override
    public List<TenantPoolSnapshot> snapshots() {
        return poolInspection.snapshots();
    }

    @Override
    public @NonNull Connection getConnection() throws SQLException {
        return currentDelegate().getConnection();
    }

    @Override
    public @NonNull Connection getConnection(final @NonNull String username, final @NonNull String password)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant database routing datasource does not allow caller-supplied credentials");
    }

    @Override
    public @NonNull ConnectionBuilder createConnectionBuilder() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant database routing datasource does not expose raw connection builders");
    }

    @Override
    public @NonNull ShardingKeyBuilder createShardingKeyBuilder() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant database routing datasource does not expose raw sharding key builders");
    }

    @Override
    public <T> @NonNull T unwrap(final @NonNull Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("tenant database routing datasource does not expose its delegates");
    }

    @Override
    public boolean isWrapperFor(final @NonNull Class<?> iface) {
        return iface.isInstance(this);
    }

    @Override
    public void close() throws Exception {
        Exception failure = null;
        final Set<DataSource> closedPools = Collections.newSetFromMap(new IdentityHashMap<>());
        for (DataSource dataSource : dataSourceByTenant.values()) {
            if (!closedPools.add(dataSource)) {
                continue;
            }
            if (dataSource instanceof AutoCloseable closeable) {
                try {
                    closeable.close();
                } catch (Exception ex) {
                    if (failure == null) {
                        failure = ex;
                    } else {
                        failure.addSuppressed(ex);
                    }
                }
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private DataSource currentDelegate() {
        final TenantId tenant = TenantContext.requireCurrent();
        if (TenantIds.SYSTEM_OPS.equals(tenant)) {
            throw new SecurityException(
                    "database isolation cannot use one ambient system-ops connection across all tenants");
        }
        final DataSource dataSource = dataSourceByTenant.get(tenant);
        if (dataSource == null) {
            throw new SecurityException("no database placement configured for tenant " + tenant);
        }
        return dataSource;
    }

    private static Map<TenantId, DataSource> validateDatabasePlacements(
            final Map<TenantId, ? extends DataSource> placements) {
        Objects.requireNonNull(placements, "dataSourceByTenant");
        final Set<DataSource> seenPools = Collections.newSetFromMap(new IdentityHashMap<>());
        placements.forEach((tenant, dataSource) -> {
            Objects.requireNonNull(tenant, "database tenant must not be null");
            Objects.requireNonNull(dataSource, "database pool must not be null");
            if (!seenPools.add(dataSource)) {
                throw new IllegalArgumentException("duplicate database pool for tenant " + tenant);
            }
        });
        return Map.copyOf(placements);
    }
}
