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
}


