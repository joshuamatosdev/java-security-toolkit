package io.github.joshuamatosdev.security.tenant.datasource.routing;

import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;

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
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Tenant Database Routing Data Source test coverage.
 *
 * <p>Why this is important to test: choosing the wrong schema or pool is a cross-tenant exposure,
 * so routing behavior needs executable coverage.
 */
class TenantDatabaseRoutingDataSourceTest {

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void routesToTheCurrentTenantsDatabasePool() throws Exception {
        final DataSource acmePool = mock(DataSource.class);
        final DataSource globexPool = mock(DataSource.class);
        final Connection acmeConnection = mock(Connection.class);
        final TenantDatabaseRoutingDataSource dataSource = new TenantDatabaseRoutingDataSource(
                Map.of(TenantIds.ACME, acmePool, TenantIds.GLOBEX, globexPool),
                TenantPoolInspection.NONE);
        when(acmePool.getConnection()).thenReturn(acmeConnection);

        TenantContext.runAs(TenantIds.ACME, () -> {
            try {
                assertThat(dataSource.getConnection()).isSameAs(acmeConnection);
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });

        verify(acmePool).getConnection();
        verify(globexPool, never()).getConnection();
    }

    @Test
    void missingPlacementFailsBeforeBorrowingAnyPool() throws Exception {
        final DataSource acmePool = mock(DataSource.class);
        final TenantDatabaseRoutingDataSource dataSource = new TenantDatabaseRoutingDataSource(
                Map.of(TenantIds.ACME, acmePool),
                TenantPoolInspection.NONE);

        TenantContext.runAs(TenantIds.GLOBEX, () -> assertThatThrownBy(dataSource::getConnection)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("no database placement configured"));

        verify(acmePool, never()).getConnection();
    }

    @Test
    void constructorRejectsSharedDataSourceAcrossTenants() {
        final DataSource sharedPool = mock(DataSource.class);

        assertThatThrownBy(() -> new TenantDatabaseRoutingDataSource(
                        Map.of(TenantIds.ACME, sharedPool, TenantIds.GLOBEX, sharedPool),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate database pool");
    }

    @Test
    void systemOpsTenantCannotUseOneAmbientDatabaseConnection() {
        final DataSource acmePool = mock(DataSource.class);
        final TenantDatabaseRoutingDataSource dataSource = new TenantDatabaseRoutingDataSource(
                Map.of(TenantIds.ACME, acmePool),
                TenantPoolInspection.NONE);

        TenantContext.runAsSystemOps(() -> assertThatThrownBy(dataSource::getConnection)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("database isolation cannot use one ambient system-ops connection"));
    }

    @Test
    void rejectsCallerSuppliedCredentials() {
        final DataSource acmePool = mock(DataSource.class);
        final TenantDatabaseRoutingDataSource dataSource = new TenantDatabaseRoutingDataSource(
                Map.of(TenantIds.ACME, acmePool),
                TenantPoolInspection.NONE);

        assertThatThrownBy(() -> dataSource.getConnection(
                        TenantTestConstants.POSTGRES_USERNAME,
                        TenantTestConstants.POSTGRES_PASSWORD))
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining(TenantTestConstants.CALLER_SUPPLIED_CREDENTIALS_MESSAGE);
    }

    @Test
    void closeClosesDistinctTenantPoolsEvenWhenTheyCompareEqual() throws Exception {
        final AtomicInteger closes = new AtomicInteger();
        final EqualCloseableDataSource acmePool = new EqualCloseableDataSource(closes);
        final EqualCloseableDataSource globexPool = new EqualCloseableDataSource(closes);
        final TenantDatabaseRoutingDataSource dataSource = new TenantDatabaseRoutingDataSource(
                Map.of(TenantIds.ACME, acmePool, TenantIds.GLOBEX, globexPool),
                TenantPoolInspection.NONE);

        dataSource.close();

        assertThat(closes).hasValue(2);
    }

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
