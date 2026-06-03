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
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SystemOpsRoutingDataSourceTest {

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void ordinaryTenantUsesRuntimePool() throws Exception {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final Connection runtimeConnection = mock(Connection.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps);
        when(runtime.getConnection()).thenReturn(runtimeConnection);

        TenantContext.runAs(TenantIds.ACME, () -> {
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
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps);
        when(systemOps.getConnection()).thenReturn(systemOpsConnection);

        TenantContext.runAsSystemOps(() -> {
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
    void rejectsCallerSuppliedCredentials() {
        final DataSource runtime = mock(DataSource.class);
        final DataSource systemOps = mock(DataSource.class);
        final SystemOpsRoutingDataSource router = new SystemOpsRoutingDataSource(runtime, systemOps);

        assertThatThrownBy(() -> router.getConnection(
                        TenantTestConstants.POSTGRES_USERNAME,
                        TenantTestConstants.POSTGRES_PASSWORD))
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining(TenantTestConstants.CALLER_SUPPLIED_CREDENTIALS_MESSAGE);
    }
}


