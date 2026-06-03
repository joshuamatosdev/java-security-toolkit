package io.github.joshuamatosdev.security.tenant.datasource.factory;

import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;

import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationMode;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationProperties;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;

class DataSourceConfigTest {

    private static final String TENANT_USER = "tenant_user";
    private static final String TENANT_PASSWORD = "tenant_password";
    private static final String ACME_ALIAS = "acme";
    private static final String ACME_JDBC_URL = "jdbc:postgresql://db.example/acme";
    private static final String SHARED_JDBC_URL = "jdbc:postgresql://db.example/shared";

    @Test
    void schemaModeRequiresTheTenantClaimSecret() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(null, null));

        assertThatThrownBy(() -> config.dataSource(sharedDataSourceProperties(), TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("tenant.binding.claim-secret");
    }

    @Test
    void schemaModeWrapsSchemaPlacementWithTenantClaimBinding() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        final DataSource dataSource = config.dataSource(sharedDataSourceProperties(), TenantPoolInspection.NONE);

        assertThat(dataSource).isInstanceOf(TenantSessionDataSourceProxy.class);
        assertThat(((TenantSessionDataSourceProxy) dataSource).poolName()).isEqualTo("tenant-schema");
    }

    @Test
    void databaseModeRequiresTheTenantClaimSecret() {
        final DataSourceConfig config = new DataSourceConfig(
                databaseIsolationProperties(),
                new TenantBindingProperties(null, null));

        assertThatThrownBy(() -> config.dataSource(sharedDataSourceProperties(), TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("tenant.binding.claim-secret");
    }

    @Test
    void databaseModeReportsTheActualTenantDatabasePools() throws Exception {
        final DataSourceConfig config = new DataSourceConfig(
                databaseIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));
        final TenantPoolInspection inspection = config.tenantPoolInspection(sharedDataSourceProperties());
        final DataSource dataSource = config.dataSource(sharedDataSourceProperties(), inspection);

        assertThat(dataSource).isInstanceOf(TenantSessionDataSourceProxy.class);
        assertThat(((TenantSessionDataSourceProxy) dataSource).poolName()).isEqualTo("tenant-database");
        assertThat(inspection.snapshots())
                .singleElement()
                .satisfies(snapshot -> {
                    assertThat(snapshot.name()).isEqualTo(TenantPoolFactory.TENANT_DATABASE_POOL_PREFIX + TenantIds.ACME);
                    assertThat(snapshot.maximumPoolSize()).isEqualTo(4);
                });

        close(dataSource);
    }

    @Test
    void idModeRequiresTheSystemOpsPassword() {
        final DataSourceConfig config = new DataSourceConfig(
                new TenantIsolationProperties(TenantIsolationMode.ID, null, null),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(sharedDataSourceProperties(), TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("tenant.binding.system-ops-password");
    }

    private static TenantIsolationProperties schemaIsolationProperties() {
        return new TenantIsolationProperties(
                TenantIsolationMode.SCHEMA,
                new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                        ACME_ALIAS,
                        new TenantIsolationProperties.SchemaTenantProperties(
                                TenantIds.ACME.toString(), "tenant_acme"))),
                null);
    }

    private static TenantIsolationProperties databaseIsolationProperties() {
        return new TenantIsolationProperties(
                TenantIsolationMode.DATABASE,
                null,
                new TenantIsolationProperties.DatabaseIsolationProperties(Map.of(
                        ACME_ALIAS,
                        new TenantIsolationProperties.DatabaseTenantProperties(
                                TenantIds.ACME.toString(),
                                ACME_JDBC_URL,
                                TENANT_USER,
                                TENANT_PASSWORD,
                                null,
                                null,
                                4,
                                0))));
    }

    private static DataSourceProperties sharedDataSourceProperties() {
        final DataSourceProperties properties = new DataSourceProperties();
        properties.setUrl(SHARED_JDBC_URL);
        properties.setUsername(TENANT_USER);
        properties.setPassword(TENANT_PASSWORD);
        return properties;
    }

    private static void close(final DataSource dataSource) throws Exception {
        if (dataSource instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }
}


