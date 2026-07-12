package io.github.joshuamatosdev.security.tenant.testfixtures;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Boots the module against a singleton PostgreSQL container whose roles and schema are created by
 * {@code db/init.sql} (mirroring the production "init-db is the schema authority" pattern). The
 * runtime pool authenticates as the NON-superuser {@code tenant_user} so RLS engages; the
 * container's bootstrap superuser is used only to seed cross-tenant fixtures (it bypasses RLS).
 *
 * <p>Why this is important to test: shared fixtures must encode the same tenant assumptions in
 * every isolation test, or passing tests could exercise different boundaries.
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

    @Autowired
    protected TenantContext tenantContext;

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

    /**
     * Truncates the shared singleton table — and the cross-tenant read-grant ledger — so each test
     * starts from a clean, deterministic state. Grants are part of that state: a leftover
     * entitlement from one test class would silently widen tenant visibility in the next.
     */
    @BeforeEach
    protected void cleanDocuments() throws Exception {
        try (Connection c = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement()) {
            st.execute("TRUNCATE TABLE " + DOCUMENT_TABLE + ", tenant_security.read_grant");
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

    /**
     * Installs a cross-tenant read entitlement as the bootstrap superuser — models the
     * platform-plane grant administration path (ordinary tenant roles cannot write the grant
     * ledger). A null {@code expiresAt} is an until-revoked grant.
     */
    protected static void grantReadAsSuperuser(
            final TenantId grantor,
            final TenantId grantee,
            final String resourceClass,
            final OffsetDateTime expiresAt)
            throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO tenant_security.read_grant"
                                + " (grantor_tenant_id, grantee_tenant_id, resource_class, expires_at)"
                                + " VALUES (?, ?, ?, ?)")) {
            ps.setObject(1, grantor.value());
            ps.setObject(2, grantee.value());
            ps.setString(3, resourceClass);
            ps.setObject(4, expiresAt);
            ps.executeUpdate();
        }
    }

    /** Removes every grant from one grantor to one grantee, bypassing RLS via the superuser. */
    protected static void revokeReadAsSuperuser(final TenantId grantor, final TenantId grantee) throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                PreparedStatement ps = c.prepareStatement(
                        "DELETE FROM tenant_security.read_grant"
                                + " WHERE grantor_tenant_id = ? AND grantee_tenant_id = ?")) {
            ps.setObject(1, grantor.value());
            ps.setObject(2, grantee.value());
            ps.executeUpdate();
        }
    }

    /** Seeds a row assigned to an organization within its tenant, bypassing RLS via the superuser. */
    protected static void seedAsSuperuser(
            final UUID id,
            final TenantId tenant,
            final OrganizationId organization,
            final String title,
            final String body)
            throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO document (id, tenant_id, organization_id, title, body) VALUES (?, ?, ?, ?, ?)")) {
            ps.setObject(1, id);
            ps.setObject(2, tenant.value());
            ps.setObject(3, organization.value());
            ps.setString(4, title);
            ps.setString(5, body);
            ps.executeUpdate();
        }
    }
}
