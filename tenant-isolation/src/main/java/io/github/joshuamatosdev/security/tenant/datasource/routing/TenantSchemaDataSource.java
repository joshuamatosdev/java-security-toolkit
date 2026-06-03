package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Tenant-aware datasource for schema-per-tenant deployments.
 *
 * <p>The active {@link TenantContext} is resolved against an allowlisted tenant-to-schema map before
 * a connection is returned. The connection is wrapped so the selected schema is reset before the
 * connection returns to the pool.
 *
 * <p>This class owns physical schema placement only. The datasource factory wraps it in {@link
 * TenantSessionDataSourceProxy} so the selected connection also receives the signed tenant claim
 * used by database defaults, checks, or RLS policies.
 */
@SystemTenantBoundary
public final class TenantSchemaDataSource extends AbstractDataSource implements TenantPoolInspection {

    private final DataSource delegate;
    private final Map<TenantId, String> schemaByTenant;
    private final TenantPoolInspection poolInspection;

    public TenantSchemaDataSource(
            final DataSource delegate,
            final Map<TenantId, String> schemaByTenant,
            final TenantPoolInspection poolInspection) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.schemaByTenant = Map.copyOf(Objects.requireNonNull(schemaByTenant, "schemaByTenant"));
        this.poolInspection = Objects.requireNonNull(poolInspection, "poolInspection");
    }

    @Override
    public List<TenantPoolSnapshot> snapshots() {
        return poolInspection.snapshots();
    }

    @Override
    public @NonNull Connection getConnection() throws SQLException {
        final String schema = requireSchemaForCurrentTenant();
        final Connection raw = delegate.getConnection();
        try {
            final String priorSchema = raw.getSchema();
            raw.setSchema(schema);
            return SchemaResetConnection.wrap(raw, priorSchema);
        } catch (SQLException | RuntimeException ex) {
            SchemaResetConnection.abortQuietly(raw);
            throw ex;
        }
    }

    @Override
    public @NonNull Connection getConnection(final @NonNull String username, final @NonNull String password)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant schema datasource does not allow caller-supplied credentials");
    }

    private String requireSchemaForCurrentTenant() {
        final TenantId tenant = TenantContext.requireCurrent();
        if (TenantIds.SYSTEM_OPS.equals(tenant)) {
            throw new SecurityException(
                    "schema isolation cannot use one ambient system-ops connection across all tenants");
        }
        final String schema = schemaByTenant.get(tenant);
        if (schema == null) {
            throw new SecurityException("no schema placement configured for tenant " + tenant);
        }
        return schema;
    }
}
