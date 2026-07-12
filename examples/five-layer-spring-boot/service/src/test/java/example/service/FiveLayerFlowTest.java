package example.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;

/**
 * Proves the five-layer posture composes on a single request: the coarse route gate (layer 2, gate
 * one), the fine-grained audited decision (layer 2, gate two), and PostgreSQL row-level security
 * under a verified tenant binding (layer 5) — in that order, each with its own observable refusal.
 *
 * <p>The perimeter layers (1 and 4) run in the {@code bff} subproject in front of this service;
 * its test proves the session boundary and token relay. The two applications share one identity
 * contract: the claims asserted here are the claims the BFF relays.
 *
 * <p>The runtime pool authenticates as the non-superuser {@code tenant_user} from
 * {@code db/init.sql}, so RLS engages exactly as it would in production.
 */
@SpringBootTest
@AutoConfigureMockMvc
class FiveLayerFlowTest {

    private static final String ACME_TENANT = "0190a000-0000-7000-8000-0000000000a1";
    private static final String GLOBEX_TENANT = "0190a000-0000-7000-8000-0000000000b2";
    private static final String ACME_ENGINEERING = "0190a000-0000-7000-8000-0000000000e1";

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
     * spring-security-test {@code jwt()} post-processor injects the authentication directly. The
     * capturing sink replaces the starter's default (bean-level back-off), the same way an
     * adopting application ships its own audit destination.
     */
    @TestConfiguration
    static class FlowTestBeans {
        @Bean
        JwtDecoder jwtDecoder() {
            return token -> {
                throw new IllegalStateException("tests fabricate JWTs with the jwt() post-processor");
            };
        }

        @Bean
        CapturingAuditSink capturingAuditSink() {
            return new CapturingAuditSink();
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private CapturingAuditSink audit;

    @Autowired
    private ObjectMapper json;

    @BeforeEach
    void reset() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement statement = connection.createStatement()) {
            statement.execute("TRUNCATE TABLE document");
        }
        audit.clear();
    }

    /**
     * A member's identity: the {@code roles} claim drives {@link RequestContexts} and the
     * authorities drive the coarse gate — the same double role the BFF-relayed token plays.
     */
    private static RequestPostProcessor member(final String subject, final String tenant, final String organization) {
        return jwt()
                .jwt(token -> {
                    token.subject(subject).claim("tenant_id", tenant).claim("roles", List.of("MEMBER"));
                    if (organization != null) {
                        token.claim("organization_id", organization);
                    }
                })
                .authorities(new SimpleGrantedAuthority("ROLE_MEMBER"));
    }

    private static RequestPostProcessor tenantAdmin(final String subject, final String tenant) {
        return jwt()
                .jwt(token -> token.subject(subject)
                        .claim("tenant_id", tenant)
                        .claim("roles", List.of("PLATFORM_ADMIN")))
                .authorities(new SimpleGrantedAuthority("ROLE_PLATFORM_ADMIN"));
    }

    /** Authenticated, tenant-bound, but holding no role the route gate accepts. */
    private static RequestPostProcessor roleLess(final String subject, final String tenant) {
        return jwt().jwt(token -> token.subject(subject).claim("tenant_id", tenant));
    }

    private static RequestPostProcessor alice() {
        return member("alice", ACME_TENANT, ACME_ENGINEERING);
    }

    private static RequestPostProcessor bob() {
        return member("bob", ACME_TENANT, ACME_ENGINEERING);
    }

    private static RequestPostProcessor mallory() {
        return member("mallory", GLOBEX_TENANT, null);
    }

    private UUID createDocument(final RequestPostProcessor identity, final String title) throws Exception {
        final String body = mvc.perform(post("/documents")
                        .with(identity)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"title\":\"" + title + "\",\"body\":\"fictional\"}"))
                .andExpect(status().isCreated())
                // id exists and the app never sent one: minted by the database's id_v7 default.
                .andExpect(jsonPath("$.id", notNullValue()))
                .andReturn()
                .getResponse()
                .getContentAsString();
        return UUID.fromString(json.readTree(body).get("id").asText());
    }

    @Test
    void aSingleRequestCrossesEveryLayerAndEachDecisionIsAudited() throws Exception {
        final UUID id = createDocument(alice(), "acme launch plan");

        // The CREATE decision was audited before the insert ran.
        final AuthorizationAuditRecord created = audit.last();
        assertThat(created.outcome()).isEqualTo(new Allow(GrantBasis.RESOURCE_OWNER));

        audit.clear();
        mvc.perform(get("/documents/" + id).with(alice()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("acme launch plan"))
                .andExpect(jsonPath("$.owner").value("alice"));

        final AuthorizationAuditRecord read = audit.last();
        assertThat(read.outcome()).isEqualTo(new Allow(GrantBasis.RESOURCE_OWNER));
    }

    @Test
    void rlsHidesForeignTenantsBeforeThePolicyEverSeesTheRow() throws Exception {
        final UUID acmeDocument = createDocument(alice(), "acme launch plan");
        audit.clear();

        // Mallory authenticates fine and holds the MEMBER role — but the row does not exist in
        // her session. Same 404 as a random id: nothing to enumerate.
        mvc.perform(get("/documents/" + acmeDocument).with(mallory()))
                .andExpect(status().isNotFound());
        mvc.perform(get("/documents/" + UUID.randomUUID()).with(mallory()))
                .andExpect(status().isNotFound());

        // Both probes still landed in the audit trail as not-found denials, not 403s.
        assertThat(audit.records()).hasSize(2);
        assertThat(audit.records())
                .allSatisfy(record -> {
                    assertThat(record.outcome())
                            .isEqualTo(new Deny(DenialReason.RESOURCE_NOT_FOUND));
                });
    }

    @Test
    void policyGrantsAreActionSpecificAndTheDenialIsAuditedBeforeThe403() throws Exception {
        final UUID id = createDocument(alice(), "acme launch plan");
        audit.clear();

        // Bob is an organization peer: the seeded policy grants organization members READ...
        mvc.perform(get("/documents/" + id).with(bob())).andExpect(status().isOk());
        assertThat(audit.last().outcome()).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));

        // ...but no rule grants MEMBER a DELETE. RLS shows him the row; the fine-grained policy
        // denies, the denial is recorded, and the starter's advice translates it to a 403.
        mvc.perform(delete("/documents/" + id).with(bob())).andExpect(status().isForbidden());

        final AuthorizationAuditRecord denied = audit.last();
        assertThat(denied.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));

        // The 403 masked nothing: alice's document is still there for alice.
        mvc.perform(get("/documents/" + id).with(alice())).andExpect(status().isOk());
    }

    @Test
    void aTenantAdminAllowIsFlaggedWideScopeInTheAuditTrail() throws Exception {
        final UUID id = createDocument(alice(), "acme launch plan");
        audit.clear();

        mvc.perform(get("/documents/" + id).with(tenantAdmin("ops", ACME_TENANT)))
                .andExpect(status().isOk());

        final AuthorizationAuditRecord allowed = audit.last();
        assertThat(allowed.outcome()).isEqualTo(new Allow(GrantBasis.WIDE_SCOPE_ADMIN));
    }

    @Test
    void theCoarseGateRefusesARoleLessTokenBeforeAnyDecisionRuns() throws Exception {
        mvc.perform(get("/documents").with(roleLess("carol", ACME_TENANT)))
                .andExpect(status().isForbidden());

        // Refused at gate one: no fine-grained decision, no audit record, no SQL.
        assertThat(audit.records()).isEmpty();
    }

    @Test
    void anUnauthenticatedRequestIsChallengedAtTheDoor() throws Exception {
        mvc.perform(get("/documents")).andExpect(status().isUnauthorized());
        assertThat(audit.records()).isEmpty();
    }

    @Test
    void listingIsScopedByTheDataPlaneAlone() throws Exception {
        createDocument(alice(), "acme launch plan");
        createDocument(mallory(), "globex payroll runbook");

        mvc.perform(get("/documents").with(alice()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("acme launch plan"));

        mvc.perform(get("/documents").with(mallory()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].title").value("globex payroll runbook"));
    }

    @Test
    void theOwnerDeletesTheirDocumentAndTheDeleteIsAudited() throws Exception {
        final UUID id = createDocument(alice(), "acme launch plan");
        audit.clear();

        mvc.perform(delete("/documents/" + id).with(alice())).andExpect(status().isNoContent());
        assertThat(audit.last().outcome()).isInstanceOf(Allow.class);

        mvc.perform(get("/documents/" + id).with(alice())).andExpect(status().isNotFound());
    }
}
