package io.github.joshuamatosdev.security.tenant.placement;

import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;

import io.github.joshuamatosdev.security.tenant.TenantIds;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Database Isolation Mode Integration test coverage.
 *
 * <p>Why this is important to test: the placement modes only satisfy the design when real database
 * containers keep tenant data separated.
 */
@SpringBootTest
class DatabaseIsolationModeIntegrationTest {

    private static final String ACME_POOL_NAME = "tenant-db-acme";
    private static final String GLOBEX_POOL_NAME = "tenant-db-globex";
    private static final PostgreSQLContainer<?> ACME_POSTGRES =
            new PostgreSQLContainer<>(AbstractRlsTest.POSTGRES_IMAGE).withInitScript("db/database-mode-acme-init.sql");
    private static final PostgreSQLContainer<?> GLOBEX_POSTGRES =
            new PostgreSQLContainer<>(AbstractRlsTest.POSTGRES_IMAGE).withInitScript("db/database-mode-globex-init.sql");

    static {
        ACME_POSTGRES.start();
        GLOBEX_POSTGRES.start();
    }

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private TenantPoolInspection tenantPoolInspection;

    @Autowired
    private TenantContext tenantContext;

    @DynamicPropertySource
    static void props(final DynamicPropertyRegistry registry) {
        registry.add("tenant.binding.claim-secret", () -> TenantTestConstants.CLAIM_SECRET);
        registry.add("tenant.isolation.mode", () -> "database");
        addTenantDatabaseProperties(registry, "acme", TenantIds.ACME.toString(), ACME_POOL_NAME, ACME_POSTGRES);
        addTenantDatabaseProperties(registry, "globex", TenantIds.GLOBEX.toString(), GLOBEX_POOL_NAME, GLOBEX_POSTGRES);
    }

    @BeforeEach
    void cleanDocuments() throws Exception {
        truncate(ACME_POSTGRES);
        truncate(GLOBEX_POSTGRES);
    }

    @Test
    void connectionBorrowRoutesToTenantDatabaseAndBindsSignedTenantClaim() {
        final JdbcTemplate jdbc = new JdbcTemplate(dataSource);

        final Map<String, Object> acmeSession = tenantContext.supplyAs(TenantIds.ACME, () ->
                jdbc.queryForMap("SELECT tenant_security.current_tenant_id() AS tenant_id"));
        final Map<String, Object> globexSession = tenantContext.supplyAs(TenantIds.GLOBEX, () ->
                jdbc.queryForMap("SELECT tenant_security.current_tenant_id() AS tenant_id"));

        assertThat(acmeSession.get("tenant_id")).isEqualTo(TenantIds.ACME.value());
        assertThat(globexSession.get("tenant_id")).isEqualTo(TenantIds.GLOBEX.value());
    }

    @Test
    void repositoryOperationsRouteToSeparateTenantDatabases() throws Exception {
        final UUID acmeId = tenantContext.supplyAs(TenantIds.ACME, () ->
                repository.save(new DocumentEntity(TenantTestConstants.ACME_DOCUMENT_TITLE, "database-acme")).getId());
        final UUID globexId = tenantContext.supplyAs(TenantIds.GLOBEX, () ->
                repository.save(new DocumentEntity(TenantTestConstants.GLOBEX_DOCUMENT_TITLE, "database-globex")).getId());

        final var acmeView = tenantContext.supplyAs(TenantIds.ACME, repository::findAll);
        final var globexView = tenantContext.supplyAs(TenantIds.GLOBEX, repository::findAll);

        assertThat(acmeView).singleElement().satisfies(document -> {
            assertThat(document.getId()).isEqualTo(acmeId);
            assertThat(document.getTenantId()).isEqualTo(TenantIds.ACME.value());
        });
        assertThat(globexView).singleElement().satisfies(document -> {
            assertThat(document.getId()).isEqualTo(globexId);
            assertThat(document.getTenantId()).isEqualTo(TenantIds.GLOBEX.value());
        });
        assertThat(countDocuments(ACME_POSTGRES)).isEqualTo(1L);
        assertThat(countDocuments(GLOBEX_POSTGRES)).isEqualTo(1L);
    }

    @Test
    void poolInspectionReportsTenantDatabasePools() {
        assertThat(tenantPoolInspection.snapshots())
                .extracting(TenantPoolSnapshot::name)
                .containsExactlyInAnyOrder(ACME_POOL_NAME, GLOBEX_POOL_NAME);
    }

    private static void addTenantDatabaseProperties(
            final DynamicPropertyRegistry registry,
            final String alias,
            final String tenantId,
            final String poolName,
            final PostgreSQLContainer<?> postgres) {
        final String prefix = "tenant.isolation.database.tenants." + alias + ".";
        registry.add(prefix + "id", () -> tenantId);
        registry.add(prefix + "jdbc-url", postgres::getJdbcUrl);
        registry.add(prefix + "username", () -> TenantTestConstants.RUNTIME_USERNAME);
        registry.add(prefix + "password", () -> TenantTestConstants.DEV_PASSWORD);
        registry.add(prefix + "pool-name", () -> poolName);
        registry.add(prefix + "maximum-pool-size", () -> 3);
        registry.add(prefix + "minimum-idle", () -> 0);
    }

    private static void truncate(final PostgreSQLContainer<?> postgres) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                        postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
                Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE document");
        }
    }

    private static long countDocuments(final PostgreSQLContainer<?> postgres) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                        postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
                Statement statement = connection.createStatement();
                var resultSet = statement.executeQuery("SELECT count(*) FROM document")) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }
}
