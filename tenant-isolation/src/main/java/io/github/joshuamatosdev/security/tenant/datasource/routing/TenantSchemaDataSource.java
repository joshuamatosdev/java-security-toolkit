package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingSource;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Tenant-aware datasource for schema-per-tenant deployments.
 *
 * <p>The active {@link TenantBindingSource} is resolved against an allowlisted tenant-to-schema map before
 * a connection is returned. The connection is wrapped so the selected schema is reset before the
 * connection returns to the pool.
 *
 * <p>This class owns physical schema placement only. The datasource factory wraps it in {@link
 * TenantSessionDataSourceProxy} so the selected connection also receives the signed tenant claim
 * used by database defaults, checks, or RLS policies.
 *
 * <p>Why this exists: tenant placement routing is the boundary that chooses the physical schema or
 * database, so it must be explicit and auditable.
 */
@SystemTenantBoundary
public final class TenantSchemaDataSource extends AbstractDataSource implements TenantPoolInspection, AutoCloseable {

    private static final Pattern POSTGRES_IDENTIFIER =
            Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");

    private final DataSource delegate;
    private final Map<TenantId, String> schemaByTenant;
    private final TenantPoolInspection poolInspection;
    private final TenantBindingSource bindingSource;

    public TenantSchemaDataSource(
            final DataSource delegate,
            final Map<TenantId, String> schemaByTenant,
            final TenantPoolInspection poolInspection,
            final TenantBindingSource bindingSource) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.schemaByTenant = validateSchemaPlacements(schemaByTenant);
        this.poolInspection = Objects.requireNonNull(poolInspection, "poolInspection");
        this.bindingSource = Objects.requireNonNull(bindingSource, "bindingSource");
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

    @Override
    public void close() throws Exception {
        if (delegate instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    private String requireSchemaForCurrentTenant() {
        final TenantId tenant = bindingSource.requireCurrent();
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

    private static Map<TenantId, String> validateSchemaPlacements(final Map<TenantId, String> placements) {
        Objects.requireNonNull(placements, "schemaByTenant");
        final Map<String, TenantId> schemaOwners = new LinkedHashMap<>();
        placements.forEach((tenant, schema) -> {
            Objects.requireNonNull(tenant, "schema tenant must not be null");
            Objects.requireNonNull(schema, "schema name must not be null");
            if (!POSTGRES_IDENTIFIER.matcher(schema).matches()) {
                throw new IllegalArgumentException("invalid schema name for tenant " + tenant + ": " + schema);
            }
            final TenantId priorOwner = schemaOwners.putIfAbsent(schema, tenant);
            if (priorOwner != null) {
                throw new IllegalArgumentException("duplicate schema name " + schema);
            }
        });
        return Map.copyOf(placements);
    }
}
