package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingSource;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Routes ID-isolation borrows to the ordinary runtime pool or the read-only system-ops pool.
 *
 * <p>Why this exists: tenant placement routing is the boundary that chooses the physical schema or
 * database, so it must be explicit and auditable.
 */
@SystemTenantBoundary
public final class SystemOpsRoutingDataSource extends AbstractDataSource implements AutoCloseable {

    private final DataSource runtime;
    private final DataSource systemOps;
    private final TenantBindingSource bindingSource;

    /**
     * Creates a context-sensitive router over the two raw pools.
     *
     * @param runtime ordinary tenant pool backed by {@code tenant_user}
     * @param systemOps read-only cross-tenant pool backed by {@code tenant_ops_user}
     */
    public SystemOpsRoutingDataSource(
            final DataSource runtime,
            final DataSource systemOps,
            final TenantBindingSource bindingSource) {
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.systemOps = Objects.requireNonNull(systemOps, "systemOps");
        this.bindingSource = Objects.requireNonNull(bindingSource, "bindingSource");
    }

    /**
     * Borrows from the pool selected by the current tenant context.
     *
     * @return a raw connection from the runtime or system-ops pool
     * @throws SQLException when the selected pool cannot provide a connection
     */
    @Override
    public @NonNull Connection getConnection() throws SQLException {
        return currentDelegate().getConnection();
    }

    /**
     * Rejects per-call credential borrows even if this router is reached directly.
     *
     * <p>The outer {@link TenantSessionDataSourceProxy} rejects this method on the primary
     * datasource. The router repeats the guard, so an accidental internal reference to the router
     * still cannot sidestep the configured non-superuser pool identities.
     *
     * @param username ignored because per-call credentials are not supported
     * @param password ignored because per-call credentials are not supported
     * @return never returns normally
     * @throws SQLFeatureNotSupportedException always
     */
    @Override
    public @NonNull Connection getConnection(final @NonNull String username, final @NonNull String password)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant routing datasource does not allow caller-supplied credentials");
    }

    @Override
    public void close() throws Exception {
        Exception failure = null;
        final Set<DataSource> closedPools = Collections.newSetFromMap(new IdentityHashMap<>());
        for (DataSource dataSource : List.of(runtime, systemOps)) {
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

    /**
     * Selects the raw pool for the current tenant context.
     *
     * <p>The explicit {@link TenantIds#SYSTEM_OPS} binding routes to the system-ops pool; any bound
     * tenant routes to the ordinary runtime pool. A missing tenant context fails closed via
     * {@link TenantBindingSource#requireCurrent()} — symmetric with the schema and database routers —
     * rather than silently defaulting to runtime. The outer proxy already fails closed first; this
     * guard makes the router safe on its own.
     *
     * @return the datasource that matches the current tenant context
     */
    private DataSource currentDelegate() {
        return TenantIds.SYSTEM_OPS.equals(bindingSource.requireCurrent()) ? systemOps : runtime;
    }
}
