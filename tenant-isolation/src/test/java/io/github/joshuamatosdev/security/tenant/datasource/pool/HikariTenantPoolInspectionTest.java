package io.github.joshuamatosdev.security.tenant.datasource.pool;

import static org.assertj.core.api.Assertions.assertThat;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.Test;

/**
 * Hikari Tenant Pool Inspection test coverage.
 *
 * <p>Why this is important to test: pool snapshots are the evidence that runtime connections use
 * the intended tenant identities.
 */
class HikariTenantPoolInspectionTest {

    private static final String RUNTIME_POOL_NAME = "tenant-runtime";
    private static final String SYSTEM_OPS_POOL_NAME = "tenant-system-ops";

    @Test
    void snapshotsExposeReadOnlyPoolStateWithoutStartingPools() {
        try (HikariDataSource runtime = pool(RUNTIME_POOL_NAME, 0, 8);
                HikariDataSource systemOps = pool(SYSTEM_OPS_POOL_NAME, 0, 2)) {
            final HikariTenantPoolInspection inspection = new HikariTenantPoolInspection(runtime, systemOps);

            assertThat(inspection.snapshots())
                .satisfiesExactly(
                    runtimeSnapshot -> {
                        assertThat(runtimeSnapshot.name()).isEqualTo(RUNTIME_POOL_NAME);
                        assertThat(runtimeSnapshot.activeConnections()).isZero();
                        assertThat(runtimeSnapshot.idleConnections()).isZero();
                        assertThat(runtimeSnapshot.totalConnections()).isZero();
                        assertThat(runtimeSnapshot.threadsAwaitingConnection()).isZero();
                        assertThat(runtimeSnapshot.minimumIdle()).isZero();
                        assertThat(runtimeSnapshot.maximumPoolSize()).isEqualTo(8);
                    },
                    systemOpsSnapshot -> {
                        assertThat(systemOpsSnapshot.name()).isEqualTo(SYSTEM_OPS_POOL_NAME);
                        assertThat(systemOpsSnapshot.activeConnections()).isZero();
                        assertThat(systemOpsSnapshot.idleConnections()).isZero();
                        assertThat(systemOpsSnapshot.totalConnections()).isZero();
                        assertThat(systemOpsSnapshot.threadsAwaitingConnection()).isZero();
                        assertThat(systemOpsSnapshot.minimumIdle()).isZero();
                        assertThat(systemOpsSnapshot.maximumPoolSize()).isEqualTo(2);
                    });
        }
    }

    private static HikariDataSource pool(final String poolName, final int minimumIdle, final int maximumPoolSize) {
        final HikariDataSource pool = new HikariDataSource();
        pool.setPoolName(poolName);
        pool.setMinimumIdle(minimumIdle);
        pool.setMaximumPoolSize(maximumPoolSize);
        return pool;
    }
}

