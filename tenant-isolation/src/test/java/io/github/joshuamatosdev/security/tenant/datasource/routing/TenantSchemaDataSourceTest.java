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
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Tenant Schema Data Source test coverage.
 *
 * <p>Why this is important to test: choosing the wrong schema or pool is a cross-tenant exposure,
 * so routing behavior needs executable coverage.
 */
class TenantSchemaDataSourceTest {

    private static final String ACME_SCHEMA = "tenant_acme";
    private static final String DEFAULT_SCHEMA = "public";

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void setsTheConfiguredSchemaAndResetsItOnClose() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.getSchema()).thenReturn(DEFAULT_SCHEMA);
        when(raw.getAutoCommit()).thenReturn(true);

        TenantContext.runAs(TenantIds.ACME, () -> {
            try (Connection guarded = dataSource.getConnection()) {
                assertThat(guarded.isWrapperFor(Connection.class)).isTrue();
                assertThat(guarded.unwrap(Connection.class)).isSameAs(guarded);
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });

        verify(raw).setSchema(ACME_SCHEMA);
        verify(raw).setSchema(DEFAULT_SCHEMA);
        verify(raw).close();
    }

    @Test
    void closedSchemaConnectionRejectsFurtherSqlWithoutReachingDelegate() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.getSchema()).thenReturn(DEFAULT_SCHEMA);
        when(raw.getAutoCommit()).thenReturn(true);

        TenantContext.runAs(TenantIds.ACME, () -> {
            try {
                final Connection guarded = dataSource.getConnection();
                guarded.close();

                assertThat(guarded.isClosed()).isTrue();
                assertThatThrownBy(() -> guarded.prepareStatement("SELECT 1"))
                        .isInstanceOf(Exception.class)
                        .hasMessageContaining("closed");
            } catch (Exception ex) {
                throw new AssertionError(ex);
            }
        });

        verify(raw, never()).prepareStatement("SELECT 1");
    }

    @Test
    void missingTenantContextFailsBeforeBorrowing() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);

        assertThatThrownBy(dataSource::getConnection)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining(TenantTestConstants.TENANT_CONTEXT_NOT_POPULATED_MESSAGE);

        verify(delegate, never()).getConnection();
    }

    @Test
    void constructorRejectsUnsafeSchemaNamesBeforeTheyReachJdbc() {
        final DataSource delegate = mock(DataSource.class);

        assertThatThrownBy(() -> new TenantSchemaDataSource(
                        delegate,
                        Map.of(TenantIds.ACME, "tenant-acme"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid schema name");
    }

    @Test
    void constructorRejectsDuplicateSchemaNamesAcrossTenants() {
        final DataSource delegate = mock(DataSource.class);

        assertThatThrownBy(() -> new TenantSchemaDataSource(
                        delegate,
                        Map.of(TenantIds.ACME, ACME_SCHEMA, TenantIds.GLOBEX, ACME_SCHEMA),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate schema name");
    }

    @Test
    void systemOpsTenantCannotUseOneAmbientSchemaConnection() {
        final DataSource delegate = mock(DataSource.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);

        TenantContext.runAsSystemOps(() -> assertThatThrownBy(dataSource::getConnection)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("schema isolation cannot use one ambient system-ops connection"));
    }

    @Test
    void rejectsCallerSuppliedCredentials() {
        final DataSource delegate = mock(DataSource.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);

        assertThatThrownBy(() -> dataSource.getConnection(
                        TenantTestConstants.POSTGRES_USERNAME,
                        TenantTestConstants.POSTGRES_PASSWORD))
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining(TenantTestConstants.CALLER_SUPPLIED_CREDENTIALS_MESSAGE);
    }

    @Test
    void doesNotExposeTheDelegatePoolOrRawBuilders() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);
        final Class<? extends DataSource> delegateClass = delegate.getClass();

        assertThat(dataSource.isWrapperFor(DataSource.class)).isTrue();
        assertThat(dataSource.unwrap(DataSource.class)).isSameAs(dataSource);
        assertThat(dataSource.isWrapperFor(delegateClass)).isFalse();
        assertThatThrownBy(() -> dataSource.unwrap(delegateClass))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("cannot be unwrapped");
        assertThatThrownBy(dataSource::createConnectionBuilder)
                .isInstanceOf(SQLFeatureNotSupportedException.class);
        assertThatThrownBy(dataSource::createShardingKeyBuilder)
                .isInstanceOf(SQLFeatureNotSupportedException.class);

        verify(delegate, never()).unwrap(delegateClass);
        verify(delegate, never()).createConnectionBuilder();
        verify(delegate, never()).createShardingKeyBuilder();
    }

    @Test
    void closesClosableDelegatePool() throws Exception {
        final CloseableDataSource delegate = mock(CloseableDataSource.class);
        final TenantSchemaDataSource dataSource = new TenantSchemaDataSource(
                delegate,
                Map.of(TenantIds.ACME, ACME_SCHEMA),
                TenantPoolInspection.NONE);

        assertThat(dataSource).isInstanceOf(AutoCloseable.class);
        dataSource.close();

        verify(delegate).close();
    }

    private interface CloseableDataSource extends DataSource, AutoCloseable {}
}
