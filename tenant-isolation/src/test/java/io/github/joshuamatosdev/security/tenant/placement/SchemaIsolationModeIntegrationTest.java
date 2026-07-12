package io.github.joshuamatosdev.security.tenant.placement;

import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;

import io.github.joshuamatosdev.security.tenant.TenantIds;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
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
 * Schema Isolation Mode Integration test coverage.
 *
 * <p>Why this is important to test: the placement modes only satisfy the design when real database
 * containers keep tenant data separated.
 */
@SpringBootTest
class SchemaIsolationModeIntegrationTest {

    private static final String ACME_SCHEMA = "tenant_acme";
    private static final String GLOBEX_SCHEMA = "tenant_globex";
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(AbstractRlsTest.POSTGRES_IMAGE).withInitScript("db/schema-mode-init.sql");

    static {
        POSTGRES.start();
    }

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private TenantContext tenantContext;

    @DynamicPropertySource
    static void props(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> TenantTestConstants.RUNTIME_USERNAME);
        registry.add("spring.datasource.password", () -> TenantTestConstants.DEV_PASSWORD);
        registry.add("tenant.binding.claim-secret", () -> TenantTestConstants.CLAIM_SECRET);
        registry.add("tenant.isolation.mode", () -> "schema");
        registry.add("tenant.isolation.schema.tenants.acme.id", TenantIds.ACME::toString);
        registry.add("tenant.isolation.schema.tenants.acme.schema", () -> ACME_SCHEMA);
        registry.add("tenant.isolation.schema.tenants.globex.id", TenantIds.GLOBEX::toString);
        registry.add("tenant.isolation.schema.tenants.globex.schema", () -> GLOBEX_SCHEMA);
    }

    @BeforeEach
    void cleanDocuments() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE tenant_acme.document, tenant_globex.document");
        }
    }

    @Test
    void connectionBorrowSelectsSchemaAndBindsSignedTenantClaim() {
        final JdbcTemplate jdbc = new JdbcTemplate(dataSource);

        final Map<String, Object> session = tenantContext.supplyAs(TenantIds.ACME, () ->
                jdbc.queryForMap("SELECT current_schema() AS schema_name, tenant_security.current_tenant_id() AS tenant_id"));

        assertThat(session.get("schema_name")).isEqualTo(ACME_SCHEMA);
        assertThat(session.get("tenant_id")).isEqualTo(TenantIds.ACME.value());
    }

    @Test
    void repositoryOperationsStayInsideTheSelectedTenantSchema() {
        final UUID acmeId = tenantContext.supplyAs(TenantIds.ACME, () ->
                repository.save(new DocumentEntity(TenantTestConstants.ACME_DOCUMENT_TITLE, "schema-acme")).getId());
        final UUID globexId = tenantContext.supplyAs(TenantIds.GLOBEX, () ->
                repository.save(new DocumentEntity(TenantTestConstants.GLOBEX_DOCUMENT_TITLE, "schema-globex")).getId());

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
    }

    @Test
    void retargetingSearchPathInsideBorrowedConnectionCannotReadAnotherTenantSchema() {
        tenantContext.runAs(TenantIds.ACME, () ->
                repository.save(new DocumentEntity(TenantTestConstants.ACME_DOCUMENT_TITLE, "schema-acme")));
        tenantContext.runAs(TenantIds.GLOBEX, () ->
                repository.save(new DocumentEntity(TenantTestConstants.GLOBEX_DOCUMENT_TITLE, "schema-globex")));

        final long globexRowsSeenFromAcme = tenantContext.supplyAs(TenantIds.ACME, this::countRowsAfterSchemaRetarget);

        assertThat(globexRowsSeenFromAcme)
                .as("schema selection is not the only isolation layer; signed-claim RLS must still filter reads")
                .isZero();
    }

    private long countRowsAfterSchemaRetarget() {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement()) {
            statement.execute("SET search_path TO " + GLOBEX_SCHEMA);
            try (var resultSet = statement.executeQuery("SELECT count(*) FROM document")) {
                resultSet.next();
                return resultSet.getLong(1);
            }
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
