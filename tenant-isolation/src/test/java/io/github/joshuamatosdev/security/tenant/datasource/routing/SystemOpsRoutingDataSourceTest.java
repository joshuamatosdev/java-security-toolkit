package io.github.joshuamatosdev.security.tenant.datasource.routing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.sql.Connection;
import java.sql.SQLFeatureNotSupportedException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * System Ops Routing Data Source test coverage.
 *
 * <p>Why this is important to test: choosing the wrong schema or pool is a cross-tenant exposure,
 * so routing behavior needs executable coverage.
 */
class SystemOpsRoutingDataSourceTest {

    private final TenantContext tenantContext = new TenantContext(() -> false);

    @Test
    void ordinaryTenantUsesRuntimePool() throws Exception {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final Connection runtimeConnection = mock(Connection.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);
        when(runtime.getConnection()).thenReturn(runtimeConnection);

        tenantContext.runAs(TenantIds.ACME, () -> {
            try {
                assertThat(router.getConnection()).isSameAs(runtimeConnection);
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });

        verify(runtime).getConnection();
        verify(systemOps, never()).getConnection();
    }

    @Test
    void systemOpsTenantUsesSystemOpsPool() throws Exception {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final Connection systemOpsConnection = mock(Connection.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);
        when(systemOps.getConnection()).thenReturn(systemOpsConnection);

        tenantContext.runAsSystemOps(() -> {
            try {
                assertThat(router.getConnection()).isSameAs(systemOpsConnection);
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });

        verify(systemOps).getConnection();
        verify(runtime, never()).getConnection();
    }

    @Test
    void missingTenantContextFailsClosedRatherThanFallingToRuntime() throws Exception {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);

        // No tenant context is bound. The router must fail closed — symmetric with the schema and
        // database routers' requireCurrent() — rather than silently default to the runtime pool.
        assertThatThrownBy(router::getConnection).isInstanceOf(SecurityException.class);

        verify(runtime, never()).getConnection();
        verify(systemOps, never()).getConnection();
    }

    @Test
    void constructorRejectsMissingRuntimePool() {
        final DataSource systemOps = mock(DataSource.class);

        assertThatThrownBy(() -> new SystemOpsRoutingDataSource(null, systemOps, tenantContext))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("runtime");
    }

    @Test
    void constructorRejectsMissingSystemOpsPool() {
        final DataSource runtime = mock(DataSource.class);

        assertThatThrownBy(() -> new SystemOpsRoutingDataSource(runtime, null, tenantContext))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("systemOps");
    }

    @Test
    void rejectsCallerSuppliedCredentials() {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);

        assertThatThrownBy(() -> router.getConnection(
                        TenantTestConstants.POSTGRES_USERNAME,
                        TenantTestConstants.POSTGRES_PASSWORD))
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining(TenantTestConstants.CALLER_SUPPLIED_CREDENTIALS_MESSAGE);
    }

    @Test
    void closesClosableRuntimeAndSystemOpsPools() throws Exception {
        final CloseableDataSource runtime = mock(CloseableDataSource.class);
        final CloseableDataSource systemOps = mock(CloseableDataSource.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);

        assertThat(router).isInstanceOf(AutoCloseable.class);
        router.close();

        verify(runtime).close();
        verify(systemOps).close();
    }

    @Test
    void closesDistinctPoolsEvenWhenTheyCompareEqual() throws Exception {
        final AtomicInteger closes = new AtomicInteger();
        final EqualCloseableDataSource runtime = new EqualCloseableDataSource(closes);
        final EqualCloseableDataSource systemOps = new EqualCloseableDataSource(closes);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps, tenantContext);

        router.close();

        assertThat(closes).hasValue(2);
    }

    private interface CloseableDataSource extends DataSource, AutoCloseable {}

    private static final class EqualCloseableDataSource extends AbstractDataSource implements AutoCloseable {

        private final AtomicInteger closes;

        private EqualCloseableDataSource(final AtomicInteger closes) {
            this.closes = closes;
        }

        @Override
        public Connection getConnection() throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("test datasource cannot create connections");
        }

        @Override
        public Connection getConnection(final String username, final String password)
                throws SQLFeatureNotSupportedException {
            throw new SQLFeatureNotSupportedException("test datasource cannot create connections");
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }

        @Override
        public boolean equals(final Object other) {
            return other instanceof EqualCloseableDataSource;
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }
}
