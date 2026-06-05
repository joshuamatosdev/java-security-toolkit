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

/**
 * Data Source Config test coverage.
 *
 * <p>Why this is important to test: pool construction wires credentials, routing, and claim signing
 * together, where a small regression can bypass least privilege.
 */
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

    @Test
    void idModeRejectsPrivilegedRuntimePoolUsername() {
        final DataSourceConfig config = new DataSourceConfig(
                new TenantIsolationProperties(TenantIsolationMode.ID, null, null),
                new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET, TenantTestConstants.DEV_PASSWORD));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TenantTestConstants.POSTGRES_USERNAME),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.username")
                .hasMessageContaining("privileged or system-ops identity");

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties("ttx"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.username")
                .hasMessageContaining("privileged or system-ops identity");
    }

    @Test
    void idModeRejectsNonPostgresRuntimePoolJdbcUrl() {
        final DataSourceConfig config = new DataSourceConfig(
                new TenantIsolationProperties(TenantIsolationMode.ID, null, null),
                new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET, TenantTestConstants.DEV_PASSWORD));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, "jdbc:h2:mem:shared"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.url")
                .hasMessageContaining("PostgreSQL");
    }

    @Test
    void idModeRejectsRuntimePoolJdbcUrlCredentialParameters() {
        final DataSourceConfig config = new DataSourceConfig(
                new TenantIsolationProperties(TenantIsolationMode.ID, null, null),
                new TenantBindingProperties(
                        TenantTestConstants.CLAIM_SECRET, TenantTestConstants.DEV_PASSWORD));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, SHARED_JDBC_URL + "?user=postgres"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.url")
                .hasMessageContaining("credential parameters");

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, SHARED_JDBC_URL + "?password=secret"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.url")
                .hasMessageContaining("credential parameters");
    }

    @Test
    void schemaModeRejectsSystemOpsRuntimePoolUsername() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TenantTestConstants.SYSTEM_OPS_USERNAME),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.username")
                .hasMessageContaining("privileged or system-ops identity");
    }

    @Test
    void schemaModeRejectsRuntimePoolPasswordWithLeadingOrTrailingWhitespace() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, SHARED_JDBC_URL, TENANT_PASSWORD + " "),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password")
                .hasMessageContaining("leading or trailing whitespace");
    }

    @Test
    void schemaModeRejectsRuntimePoolPasswordWithControlCharacters() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, SHARED_JDBC_URL, TENANT_PASSWORD + "\nforged"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.password")
                .hasMessageContaining("control characters");
    }

    @Test
    void schemaModeRejectsNonPostgresRuntimePoolJdbcUrl() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, "jdbc:mysql://db.example/shared"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.url")
                .hasMessageContaining("PostgreSQL");
    }

    @Test
    void schemaModeRejectsRuntimePoolPostgresJdbcUrlPrefixWithDriverInvalidCase() {
        final DataSourceConfig config = new DataSourceConfig(
                schemaIsolationProperties(),
                new TenantBindingProperties(TenantTestConstants.CLAIM_SECRET, null));

        assertThatThrownBy(() -> config.dataSource(
                        sharedDataSourceProperties(TENANT_USER, "jdbc:POSTGRESQL://db.example/shared"),
                        TenantPoolInspection.NONE))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("spring.datasource.url")
                .hasMessageContaining("PostgreSQL");
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
        return sharedDataSourceProperties(TENANT_USER);
    }

    private static DataSourceProperties sharedDataSourceProperties(final String username) {
        return sharedDataSourceProperties(username, SHARED_JDBC_URL);
    }

    private static DataSourceProperties sharedDataSourceProperties(
            final String username,
            final String jdbcUrl) {
        return sharedDataSourceProperties(username, jdbcUrl, TENANT_PASSWORD);
    }

    private static DataSourceProperties sharedDataSourceProperties(
            final String username,
            final String jdbcUrl,
            final String password) {
        final DataSourceProperties properties = new DataSourceProperties();
        properties.setUrl(jdbcUrl);
        properties.setUsername(username);
        properties.setPassword(password);
        return properties;
    }

    private static void close(final DataSource dataSource) throws Exception {
        if (dataSource instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }
}
