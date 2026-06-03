package io.github.joshuamatosdev.security.tenant.testfixtures;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.UUID;

/**
 * Boots the module against a singleton PostgreSQL container whose roles and schema are created by
 * {@code db/init.sql} (mirroring the production "init-db is the schema authority" pattern). The
 * runtime pool authenticates as the NON-superuser {@code tenant_user} so RLS engages; the
 * container's bootstrap superuser is used only to seed cross-tenant fixtures (it bypasses RLS).
 */
@SpringBootTest
public abstract class AbstractRlsTest {

    protected static final String CLAIM_SECRET = TenantTestConstants.CLAIM_SECRET;
    public static final String POSTGRES_IMAGE = "postgres:18-alpine";
    protected static final String INIT_SCRIPT = "db/init.sql";
    protected static final String RUNTIME_USERNAME = TenantTestConstants.RUNTIME_USERNAME;
    protected static final String SYSTEM_OPS_USERNAME = TenantTestConstants.SYSTEM_OPS_USERNAME;
    protected static final String DEV_PASSWORD = TenantTestConstants.DEV_PASSWORD;
    protected static final String DOCUMENT_TABLE = "document";

    // Singleton container: started once on first use, shared by every test class, reaped by Ryuk at
    // JVM exit. One stable container instead of one per test class.
    protected static final PostgreSQLContainer<?> POSTGRES;

    static {
        POSTGRES = new PostgreSQLContainer<>(POSTGRES_IMAGE).withInitScript(INIT_SCRIPT);
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void props(final DynamicPropertyRegistry registry) {
        // Runtime pool: the non-superuser tenant_user — this is the identity RLS evaluates against.
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> RUNTIME_USERNAME);
        registry.add("spring.datasource.password", () -> DEV_PASSWORD);
        registry.add("tenant.binding.claim-secret", () -> CLAIM_SECRET);
        registry.add("tenant.binding.system-ops-password", () -> DEV_PASSWORD);
    }

    /** Truncates the shared singleton table so each test starts from a clean, deterministic state. */
    @BeforeEach
    protected void cleanDocuments() throws Exception {
        try (Connection c = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement()) {
            st.execute("TRUNCATE TABLE " + DOCUMENT_TABLE);
        }
    }

    /** Inserts a row as the bootstrap superuser, which bypasses RLS — models a privileged seed path. */
    protected static void seedAsSuperuser(final UUID id, final TenantId tenant, final String title, final String body)
            throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                PreparedStatement ps =
                        c.prepareStatement("INSERT INTO document (id, tenant_id, title, body) VALUES (?, ?, ?, ?)")) {
            ps.setObject(1, id);
            ps.setObject(2, tenant.value());
            ps.setString(3, title);
            ps.setString(4, body);
            ps.executeUpdate();
        }
    }
}
