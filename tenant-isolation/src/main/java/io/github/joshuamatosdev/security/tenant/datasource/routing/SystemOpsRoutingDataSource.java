package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import javax.sql.DataSource;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Routes ID-isolation borrows to the ordinary runtime pool or the read-only system-ops pool.
 */
@SystemTenantBoundary
public final class SystemOpsRoutingDataSource extends AbstractDataSource {

    private final DataSource runtime;
    private final DataSource systemOps;

    /**
     * Creates a context-sensitive router over the two raw pools.
     *
     * @param runtime ordinary tenant pool backed by {@code tenant_user}
     * @param systemOps read-only cross-tenant pool backed by {@code tenant_ops_user}
     */
    public SystemOpsRoutingDataSource(final DataSource runtime, final DataSource systemOps) {
        this.runtime = runtime;
        this.systemOps = systemOps;
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

    /**
     * Selects the raw pool for the current tenant context.
     *
     * <p>Only the explicit {@link TenantIds#SYSTEM_OPS} binding routes to the system-ops pool.
     * All other states, including missing tenant context, default to the ordinary runtime pool; the
     * outer proxy is responsible for failing closed when the context is missing.
     *
     * @return the datasource that matches the current tenant context
     */
    private DataSource currentDelegate() {
        return TenantContext.current()
                .filter(TenantIds.SYSTEM_OPS::equals)
                .map(ignored -> systemOps)
                .orElse(runtime);
    }
}

