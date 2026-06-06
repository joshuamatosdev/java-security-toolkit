package io.github.joshuamatosdev.security.tenant.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Tenant Isolation Properties test coverage.
 *
 * <p>Why this is important to test: configuration mistakes can route tenant data through the wrong
 * placement mode or unsafe credentials before SQL ever runs.
 */
class TenantIsolationPropertiesTest {

    private static final String ACME_ALIAS = "acme";
    private static final String ACME_SCHEMA = "tenant_acme";
    private static final String UNSAFE_ACME_SCHEMA = "tenant-acme";
    private static final String ACME_JDBC_URL = "jdbc:postgresql://db/acme";
    private static final String GLOBEX_ALIAS = "globex";
    private static final String GLOBEX_JDBC_URL = "jdbc:postgresql://db/globex";
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
    void schemaModeRejectsNonCanonicalTenantIds() {
        assertThatThrownBy(() -> new TenantIsolationProperties(
                        TenantIsolationMode.SCHEMA,
                        new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                                ACME_ALIAS,
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        "190a000-0000-7000-8000-0000000000a1", ACME_SCHEMA))),
                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid UUID id");
    }

    @Test
    void schemaModeRejectsDuplicateSchemaNamesAcrossTenants() {
        assertThatThrownBy(() -> new TenantIsolationProperties(
                        TenantIsolationMode.SCHEMA,
                        new TenantIsolationProperties.SchemaIsolationProperties(Map.of(
                                ACME_ALIAS,
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        TenantIds.ACME.toString(), ACME_SCHEMA),
                                "globex",
                                new TenantIsolationProperties.SchemaTenantProperties(
                                        TenantIds.GLOBEX.toString(), ACME_SCHEMA))),
                        null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate schema name")
                .hasMessageContaining("tenant.isolation.schema.tenants");
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
    void databaseModeRejectsDriverClassNameWithRawWhitespace() {
        assertThatThrownBy(() -> databaseModeProperties(
                        databaseTenant(TENANT_PASSWORD, POSTGRES_DRIVER + " ", null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid driver-class-name");
    }

    @Test
    void databaseModeRejectsUsernameWithRawWhitespace() {
        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        TENANT_USER + " ",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not include leading or trailing whitespace");
    }

    @Test
    void databaseModeRejectsUsernameWithControlCharacters() {
        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        TENANT_USER + "\u0000",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not contain control characters");
    }

    @Test
    void databaseModeRejectsKnownPrivilegedOrSystemOpsUsernames() {
        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        "postgres",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not be a privileged or system-ops identity");

        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        "ttx",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not be a privileged or system-ops identity");

        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        "tenant_ops_user",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not be a privileged or system-ops identity");

        assertThatThrownBy(() -> databaseModeProperties(new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL,
                        "tenant_bypass",
                        TENANT_PASSWORD,
                        POSTGRES_DRIVER,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username must not be a privileged or system-ops identity");
    }

    @Test
    void databaseModeRejectsPasswordWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(TENANT_PASSWORD + " ", null, null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password must not include leading or trailing whitespace");
    }

    @Test
    void databaseModeRejectsPasswordWithControlCharacters() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(TENANT_PASSWORD + "\nforged", null, null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("password must not contain control characters");
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
    void databaseModeRejectsDuplicateJdbcUrlsAcrossTenants() {
        assertThatThrownBy(() -> databaseModeProperties(Map.of(
                        ACME_ALIAS,
                        databaseTenant(
                                TenantIds.ACME.toString(),
                                ACME_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                STABLE_POOL_NAME,
                                null,
                                null),
                        GLOBEX_ALIAS,
                        databaseTenant(
                                TenantIds.GLOBEX.toString(),
                                ACME_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                "tenant-db-globex",
                                null,
                                null))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate jdbc-url")
                .hasMessageContaining("tenant.isolation.database.tenants");
    }

    @Test
    void databaseModeRejectsNonJdbcUrls() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        "https://db.example/acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid jdbc-url");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        "jdbc:",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid jdbc-url");
    }

    @Test
    void databaseModeRejectsNonPostgresJdbcUrls() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        "jdbc:h2:mem:acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be a PostgreSQL jdbc-url");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        "jdbc:mysql://db/acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be a PostgreSQL jdbc-url");
    }

    @Test
    void databaseModeRejectsPostgresJdbcUrlPrefixWithDriverInvalidCase() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        "jdbc:POSTGRESQL://db/acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be a PostgreSQL jdbc-url");
    }

    @Test
    void databaseModeRejectsJdbcUrlUnsafeParameters() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?user=postgres",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url")
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?password=secret",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url")
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?authenticationPluginClassName=com.example.SecretPlugin",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url")
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?currentSchema=tenant_acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url")
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?options=-c%20search_path=tenant_acme",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url")
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");
    }

    @Test
    void databaseModeRejectsJdbcUrlTargetAndTrustOverrides() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?PGHOST=evil.example",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?PGDBNAME=globex",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?targetServerType=preferSecondary",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?sslrootcert=/run/secrets/root.crt",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?sslmode=disable",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?channelBinding=disable",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?scramMaxIterations=0",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?allowEncodingChanges=true",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?ssl=false",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");

        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "?preferQueryMode=simple",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unsafe credential, target, trust, plugin, or session parameters");
    }

    @Test
    void databaseModeRejectsJdbcUrlsWithRawWhitespace() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + " ",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid jdbc-url");
    }

    @Test
    void databaseModeRejectsJdbcUrlsWithControlCharacters() {
        assertThatThrownBy(() -> databaseModeProperties(databaseTenant(
                        TenantIds.ACME.toString(),
                        ACME_JDBC_URL + "\u0000",
                        TENANT_PASSWORD,
                        null,
                        STABLE_POOL_NAME,
                        null,
                        null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jdbc-url must not contain control characters");
    }

    @Test
    void databaseModeRejectsDuplicatePoolNamesAcrossTenants() {
        assertThatThrownBy(() -> databaseModeProperties(Map.of(
                        ACME_ALIAS,
                        databaseTenant(
                                TenantIds.ACME.toString(),
                                ACME_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                STABLE_POOL_NAME,
                                null,
                                null),
                        GLOBEX_ALIAS,
                        databaseTenant(
                                TenantIds.GLOBEX.toString(),
                                GLOBEX_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                STABLE_POOL_NAME,
                                null,
                                null))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate pool-name")
                .hasMessageContaining("tenant.isolation.database.tenants");
    }

    @Test
    void databaseModeRejectsExplicitPoolNameCollidingWithAnotherTenantsDefaultPoolName() {
        assertThatThrownBy(() -> databaseModeProperties(Map.of(
                        ACME_ALIAS,
                        databaseTenant(
                                TenantIds.ACME.toString(),
                                ACME_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                null,
                                null,
                                null),
                        GLOBEX_ALIAS,
                        databaseTenant(
                                TenantIds.GLOBEX.toString(),
                                GLOBEX_JDBC_URL,
                                TENANT_PASSWORD,
                                null,
                                "tenant-db-" + TenantIds.ACME,
                                null,
                                null))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("duplicate pool-name")
                .hasMessageContaining("tenant.isolation.database.tenants");
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
        return databaseModeProperties(Map.of(ACME_ALIAS, tenant));
    }

    private static TenantIsolationProperties databaseModeProperties(
            final Map<String, TenantIsolationProperties.DatabaseTenantProperties> tenants) {
        return new TenantIsolationProperties(
                TenantIsolationMode.DATABASE,
                null,
                new TenantIsolationProperties.DatabaseIsolationProperties(tenants));
    }

    private static TenantIsolationProperties.DatabaseTenantProperties databaseTenant(
            final String password,
            final String driverClassName,
            final String poolName,
            final Integer maximumPoolSize,
            final Integer minimumIdle) {
        return databaseTenant(
                TenantIds.ACME.toString(),
                ACME_JDBC_URL,
                password,
                driverClassName,
                poolName,
                maximumPoolSize,
                minimumIdle);
    }

    private static TenantIsolationProperties.DatabaseTenantProperties databaseTenant(
            final String tenantId,
            final String jdbcUrl,
            final String password,
            final String driverClassName,
            final String poolName,
            final Integer maximumPoolSize,
            final Integer minimumIdle) {
        return new TenantIsolationProperties.DatabaseTenantProperties(
                tenantId,
                jdbcUrl,
                TENANT_USER,
                password,
                driverClassName,
                poolName,
                maximumPoolSize,
                minimumIdle);
    }
}
