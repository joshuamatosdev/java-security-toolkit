package io.github.joshuamatosdev.security.tenant.datasource.pool;

import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.HikariPoolMXBean;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Objects;

/**
 * Adapts one Hikari pool to the module's stable read-only pool snapshot shape.
 *
 * <p>Why this exists: pool inspection makes runtime pool identity observable so tests can prove
 * least-privilege tenant connections are really in use.
 */
@SystemTenantBoundary
final class HikariTenantPoolSnapshotSource implements TenantPoolSnapshotSource {

    private final HikariDataSource pool;

    /**
     * Creates a snapshot source for one raw Hikari pool.
     *
     * @param pool raw tenant pool, retained only for metrics inspection
     */
    HikariTenantPoolSnapshotSource(final HikariDataSource pool) {
        this.pool = Objects.requireNonNull(pool, "pool");
    }

    /**
     * Converts the current Hikari state into the stable tenant-pool snapshot.
     *
     * @return read-only pool state
     */
    @Override
    public TenantPoolSnapshot snapshot() {
        final HikariPoolMXBean mxBean = pool.getHikariPoolMXBean();
        return new TenantPoolSnapshot(
                pool.getPoolName(),
                activeConnections(mxBean),
                idleConnections(mxBean),
                totalConnections(mxBean),
                threadsAwaitingConnection(mxBean),
                pool.getMinimumIdle(),
                pool.getMaximumPoolSize());
    }

    /**
     * Returns the active connection count, defaulting to zero before Hikari creates its MXBean.
     *
     * @param mxBean optional Hikari pool metrics bean
     * @return active connection count, or zero when the pool has not started
     */
    private static int activeConnections(final HikariPoolMXBean mxBean) {
        return mxBean == null ? 0 : mxBean.getActiveConnections();
    }

    /**
     * Returns the idle connection count, defaulting to zero before Hikari creates its MXBean.
     *
     * @param mxBean optional Hikari pool metrics bean
     * @return idle connection count, or zero when the pool has not started
     */
    private static int idleConnections(final HikariPoolMXBean mxBean) {
        return mxBean == null ? 0 : mxBean.getIdleConnections();
    }

    /**
     * Returns the total connection count, defaulting to zero before Hikari creates its MXBean.
     *
     * @param mxBean optional Hikari pool metrics bean
     * @return total connection count, or zero when the pool has not started
     */
    private static int totalConnections(final HikariPoolMXBean mxBean) {
        return mxBean == null ? 0 : mxBean.getTotalConnections();
    }

    /**
     * Returns the waiting-thread count, defaulting to zero before Hikari creates its MXBean.
     *
     * @param mxBean optional Hikari pool metrics bean
     * @return waiting-thread count, or zero when the pool has not started
     */
    private static int threadsAwaitingConnection(final HikariPoolMXBean mxBean) {
        return mxBean == null ? 0 : mxBean.getThreadsAwaitingConnection();
    }
}


