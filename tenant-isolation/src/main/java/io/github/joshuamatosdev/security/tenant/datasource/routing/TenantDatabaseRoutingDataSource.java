package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import java.sql.Connection;
import java.sql.ConnectionBuilder;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.ShardingKeyBuilder;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Tenant-aware datasource for database-per-tenant deployments.
 *
 * <p>The active {@link TenantContext} is resolved against an allowlisted tenant-to-datasource map.
 * The selected tenant pool is the primary isolation boundary. {@link TenantDataSourceFactory} wraps
 * this router in {@link TenantSessionDataSourceProxy} so each selected database also receives the
 * signed tenant claim used by database defaults, checks, or RLS policies.
 */
@SystemTenantBoundary
public final class TenantDatabaseRoutingDataSource extends AbstractDataSource implements TenantPoolInspection, AutoCloseable {

    private final Map<TenantId, DataSource> dataSourceByTenant;
    private final TenantPoolInspection poolInspection;

    public TenantDatabaseRoutingDataSource(
            final Map<TenantId, ? extends DataSource> dataSourceByTenant,
            final TenantPoolInspection poolInspection) {
        this.dataSourceByTenant = Map.copyOf(Objects.requireNonNull(dataSourceByTenant, "dataSourceByTenant"));
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
        for (DataSource dataSource : new LinkedHashSet<>(dataSourceByTenant.values())) {
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
}

