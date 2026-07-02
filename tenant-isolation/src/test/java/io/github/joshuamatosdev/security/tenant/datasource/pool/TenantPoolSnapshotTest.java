package io.github.joshuamatosdev.security.tenant.datasource.pool;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Tenant Pool Snapshot test coverage.
 *
 * <p>Why this is important to test: pool snapshots are the evidence that runtime connections use
 * the intended tenant identities.
 */
class TenantPoolSnapshotTest {

    private static final String POOL_NAME = "tenant-runtime";

    @Test
    void constructorRejectsMalformedPoolNames() {
        assertThatThrownBy(() -> new TenantPoolSnapshot("", 0, 0, 0, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("name must not be blank");

        assertThatThrownBy(() -> new TenantPoolSnapshot(" tenant-runtime", 0, 0, 0, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("name must not include leading or trailing whitespace");

        assertThatThrownBy(() -> new TenantPoolSnapshot("tenant-runtime\nforged", 0, 0, 0, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("name must not contain control characters");
    }

    @Test
    void constructorRejectsNegativeMetricCounts() {
        assertThatThrownBy(() -> new TenantPoolSnapshot(POOL_NAME, -1, 0, 0, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("activeConnections");

        assertThatThrownBy(() -> new TenantPoolSnapshot(POOL_NAME, 0, -1, 0, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("idleConnections");

        assertThatThrownBy(() -> new TenantPoolSnapshot(POOL_NAME, 0, 0, -1, 0, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("totalConnections");

        assertThatThrownBy(() -> new TenantPoolSnapshot(POOL_NAME, 0, 0, 0, -1, 0, 10))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("threadsAwaitingConnection");
    }

    @Test
    void constructorAcceptsWeaklyConsistentConnectionCounts() {
        // The counts are separate live reads of a concurrent pool: a connection mid-transition or
        // in Hikari's reserved state makes total differ from active + idle. The snapshot must
        // accept that — a health/metrics read must never throw because the pool was busy.
        assertThatCode(() -> new TenantPoolSnapshot(POOL_NAME, 1, 2, 4, 0, 0, 10))
                .doesNotThrowAnyException();

        assertThatCode(() -> new TenantPoolSnapshot(POOL_NAME, 3, 0, 2, 0, 0, 10))
                .doesNotThrowAnyException();
    }
}
