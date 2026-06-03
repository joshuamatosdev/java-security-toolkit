package io.github.joshuamatosdev.security.tenant.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TenantIsolationPropertiesTest {

    private static final String ACME_ALIAS = "acme";
    private static final String ACME_SCHEMA = "tenant_acme";
    private static final String UNSAFE_ACME_SCHEMA = "tenant-acme";
    private static final String ACME_JDBC_URL = "jdbc:postgresql://db/acme";
    private static final String TENANT_USER = "tenant_user";
    private static final String TENANT_PASSWORD = "tenant_password";
    private static final String POSTGRES_DRIVER = "org.postgresql.Driver";
    private static final String STABLE_POOL_NAME = "tenant-db-acme";

    @Test
    void defaultsToIdIsolationWhenModeIsOmitted() {
        final TenantIsolationProperties properties = new TenantIsolationProperties(null, null, null);

        assertThat(properties.mode()).isEqualTo(TenantIsolationMode.ID);
    }

    @Test
    void schemaModeBuildsTypedPlacementMap() {
        final TenantIsolationProperties properties = new TenantIsolationProperties(
                TenantIsolationMode.SCHEMA,
                new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                        ACME_ALIAS,
                        new TenantIsolationProperties.SchemaTenantProperties(
                                TenantIds.ACME.toString(), ACME_SCHEMA))),
                null);

        assertThat(properties.schemaPlacements()).containsEntry(TenantIds.ACME, ACME_SCHEMA);
    }

    @Test
    void schemaModeRejectsUnsafeSchemaNames() {
        assertThatThrownBy(() -> new TenantIsolationProperties(
                        TenantIsolationMode.SCHEMA,
                        new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                                ACME_ALIAS,
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        TenantIds.ACME.toString(), UNSAFE_ACME_SCHEMA))),
                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid schema name");
    }

    @Test
    void databaseModeRequiresACompletePlacement() {
        assertThatThrownBy(() -> new TenantIsolationProperties(
                        TenantIsolationMode.DATABASE,
                        null,
                        new TenantIsolationProperties.DatabaseIsolationProperties(Map.of(
                                ACME_ALIAS,
                                new TenantIsolationProperties.DatabaseTenantProperties(
                                        TenantIds.ACME.toString(),
                                        ACME_JDBC_URL,
                                        TENANT_USER,
                                        "",
                                        null,
                                        null,
                                        null,
                                        null)))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("requires password");
    }

    @Test
    void databaseModeRejectsBlankOptionalDriverClassName() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(TENANT_PASSWORD, " ", null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-blank driver-class-name");
    }

    @Test
    void databaseModeRejectsBlankOptionalPoolName() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(TENANT_PASSWORD, null, " ", null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-blank pool-name");
    }

    @Test
    void databaseModeRejectsUnstableOptionalPoolName() {
        assertThatThrownBy(() -> databaseModeProperties(
                        databaseTenant(TENANT_PASSWORD, null, "tenant db acme", null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid pool-name");
    }

    @Test
    void databaseModeRejectsMinimumIdleAboveMaximumPoolSize() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(TENANT_PASSWORD, null, null, 4, 5)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("minimum-idle")
                .hasMessageContaining("maximum-pool-size");
    }

    @Test
    void databaseModeAcceptsStableOptionalPoolAndDriverValues() {
        final TenantIsolationProperties properties =
                databaseModeProperties(databaseTenant(TENANT_PASSWORD, POSTGRES_DRIVER, STABLE_POOL_NAME, 4, 4));

        assertThat(properties.databasePlacements())
                .containsEntry(
                        TenantIds.ACME,
                        new TenantIsolationProperties.DatabaseTenantProperties(
                                TenantIds.ACME.toString(),
                                ACME_JDBC_URL,
                                TENANT_USER,
                                TENANT_PASSWORD,
                                POSTGRES_DRIVER,
                                STABLE_POOL_NAME,
                                4,
                                4));
    }

    @Test
    void duplicateTenantIdsAreRejected() {
        assertThatThrownBy(() -> new TenantIsolationProperties(
                        TenantIsolationMode.SCHEMA,
                        new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                                ACME_ALIAS,
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        TenantIds.ACME.toString(), ACME_SCHEMA),
                                "also-acme",
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        TenantIds.ACME.toString(), "tenant_acme_two"))),
                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate tenant id");
    }

    private static TenantIsolationProperties databaseModeProperties(
            final TenantIsolationProperties.DatabaseTenantProperties tenant) {
        return new TenantIsolationProperties(
                TenantIsolationMode.DATABASE,
                null,
                new TenantIsolationProperties.DatabaseIsolationProperties(Map.of(ACME_ALIAS, tenant)));
    }

    private static TenantIsolationProperties.DatabaseTenantProperties databaseTenant(
            final String password,
            final String driverClassName,
            final String poolName,
            final Integer maximumPoolSize,
            final Integer minimumIdle) {
        return new TenantIsolationProperties.DatabaseTenantProperties(
                TenantIds.ACME.toString(),
                ACME_JDBC_URL,
                TENANT_USER,
                password,
                driverClassName,
                poolName,
                maximumPoolSize,
                minimumIdle);
    }
}
