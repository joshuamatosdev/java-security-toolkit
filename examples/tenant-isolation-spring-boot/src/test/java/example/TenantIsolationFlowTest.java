package example;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;

/**
 * Proves the walkthrough's claims end to end: HTTP request with a verified JWT, the one filter this
 * application owns, a repository with zero tenant predicates, and real PostgreSQL row-level
 * security deciding what each tenant and organization can see.
 *
 * <p>The runtime pool authenticates as the non-superuser {@code tenant_user} from
 * {@code db/init.sql}, so RLS engages exactly as it would in production. The container's bootstrap
 * superuser is used only to reset state between tests (it bypasses RLS).
 */
@SpringBootTest
@AutoConfigureMockMvc
class TenantIsolationFlowTest {

    private static final TenantId ACME = TenantIds.ACME;
    private static final TenantId GLOBEX = TenantIds.GLOBEX;
    private static final OrganizationId ACME_ENGINEERING =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
    private static final OrganizationId ACME_SALES =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e2");

    // Singleton container: started once, shared by every test method, reaped by Ryuk at JVM exit.
    private static final PostgreSQLContainer<?> POSTGRES;

    static {
        POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine").withInitScript("db/init.sql");
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void props(final DynamicPropertyRegistry registry) {
        // Runtime pool: the non-superuser tenant_user — the identity RLS evaluates against.
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> "tenant_user");
        registry.add("spring.datasource.password", () -> "local_dev_only");
        registry.add(
                "tenant.binding.claim-secret",
                () -> "local-dev-tenant-claim-secret-not-production-32-bytes");
        registry.add("tenant.binding.system-ops-password", () -> "local_dev_only");
    }

    /**
     * The security chain needs a decoder bean to start, but no test presents a real token: the
     * spring-security-test {@code jwt()} post-processor injects the authentication directly.
     */
    @TestConfiguration
    static class NoRealTokens {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> {
                throw new IllegalStateException("tests fabricate JWTs with the jwt() post-processor");
            };
        }
    }

    @Autowired
    private MockMvc mvc;

    @BeforeEach
    void cleanNotes() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE note");
        }
    }

    private static RequestPostProcessor tenantUser(final TenantId tenant) {
        return jwt().jwt(jwt -> jwt.claim("tenant_id", tenant.value().toString()));
    }

    private static RequestPostProcessor organizationUser(
            final TenantId tenant, final OrganizationId organization) {
        return jwt().jwt(jwt -> jwt.claim("tenant_id", tenant.value().toString())
                .claim("organization_id", organization.value().toString()));
    }

    private void createNote(final RequestPostProcessor identity, final String title) throws Exception {
        mvc.perform(post("/notes")
                        .with(identity)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + title + "\",\"body\":\"fictional\"}"))
                .andExpect(status().isCreated())
                // id exists and the app never sent one: minted by the database's id_v7 default.
                .andExpect(jsonPath("$.id", notNullValue()));
    }

    @Test
    void tenantSeesOnlyItsOwnRows() throws Exception {
        createNote(tenantUser(ACME), "acme launch plan");
        createNote(tenantUser(GLOBEX), "globex payroll runbook");

        mvc.perform(get("/notes").with(tenantUser(ACME)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("acme launch plan"));

        mvc.perform(get("/notes").with(tenantUser(GLOBEX)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("globex payroll runbook"));
    }

    @Test
    void organizationScopeSubdividesTenantWithoutReplacingIt() throws Exception {
        createNote(organizationUser(ACME, ACME_ENGINEERING), "engineering oncall notes");
        createNote(organizationUser(ACME, ACME_SALES), "sales pipeline notes");
        createNote(tenantUser(ACME), "tenant-wide policy");

        // An organization-bound session sees only its organization's rows; the tenant-wide row
        // (organization_id NULL) stays with organization-unscoped sessions.
        mvc.perform(get("/notes").with(organizationUser(ACME, ACME_ENGINEERING)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("engineering oncall notes"));

        // An organization-unscoped session sees the whole tenant.
        mvc.perform(get("/notes").with(tenantUser(ACME)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));

        // The organization dimension never crosses the tenant boundary.
        mvc.perform(get("/notes").with(tenantUser(GLOBEX)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void authenticatedRequestWithoutTenantClaimIsForbidden() throws Exception {
        mvc.perform(get("/notes").with(jwt())).andExpect(status().isForbidden());
    }

    @Test
    void malformedTenantOrOrganizationClaimIsForbidden() throws Exception {
        mvc.perform(get("/notes").with(jwt().jwt(token -> token.claim("tenant_id", "not-a-uuid"))))
                .andExpect(status().isForbidden());
        mvc.perform(get("/notes").with(jwt().jwt(token -> token
                        .claim("tenant_id", ACME.value().toString())
                        .claim("organization_id", "not-a-uuid"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedRequestIsRejectedBeforeAnyDataAccess() throws Exception {
        mvc.perform(get("/notes")).andExpect(status().isUnauthorized());
    }
}
