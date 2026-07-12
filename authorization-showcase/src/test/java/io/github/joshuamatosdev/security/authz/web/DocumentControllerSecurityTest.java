package io.github.joshuamatosdev.security.authz.web;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.testfixtures.CapturingAuditSink;
import io.github.joshuamatosdev.security.authz.web.document.DocumentDirectory;
import io.github.joshuamatosdev.security.authz.web.document.DocumentRoutes;
import io.github.joshuamatosdev.security.authz.web.health.HealthRoutes;
import io.github.joshuamatosdev.security.authz.web.config.SecurityConfig;
import io.github.joshuamatosdev.security.authz.web.support.DemoAccounts;
import io.github.joshuamatosdev.security.authz.web.support.RequestContextResolver;
import io.github.joshuamatosdev.security.authz.web.support.RequestHeaders;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves the two gates together over HTTP. The coarse request gate ({@link SecurityConfig}) enforces
 * authentication and deny-by-default at the route; the fine-grained {@code AuthorizationService}
 * decides resource access and surfaces a denial as 403. Tenant and organization arrive as the
 * headers a gateway would inject.
 *
 * <p>Why this is important to test: authorization bugs become route-level privilege bugs, so the
 * web boundary must prove deny-by-default and scoped access behavior.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentControllerSecurityTest {

    private static final PostgreSQLContainer<?> POSTGRES =
        new PostgreSQLContainer<>("postgres:18-alpine").withInitScript("db/layered-authz-init.sql");
    private static final String RUNTIME_USERNAME = "authz_user";
    private static final String DEV_PASSWORD = "local_dev_only";
    private static final String DOCUMENT_TABLE = "document";
    private static final ResourceId OWNED_BY_MEMBER_ID =
        ResourceId.fromString("33333333-3333-3333-3333-333333333333");
    private static final ResourceId OWNED_BY_OTHER_ID =
        ResourceId.fromString("44444444-4444-4444-4444-444444444444");
    private static final ResourceId OWNED_IN_OTHER_TENANT_ID =
        ResourceId.fromString("66666666-6666-6666-6666-666666666666");
    private static final String ACME = DocumentDirectory.ACME.value().toString();
    private static final String GLOBEX = "99999999-9999-9999-9999-999999999999";
    private static final TenantId OTHER_TENANT = TenantId.fromString(GLOBEX);
    private static final String ENGINEERING = DocumentDirectory.ENGINEERING.value().toString();
    private static final String SALES = "23232323-2323-2323-2323-232323232323";
    private static final String OWNED_BY_MEMBER = OWNED_BY_MEMBER_ID.value().toString();
    private static final String OWNED_BY_OTHER = OWNED_BY_OTHER_ID.value().toString();
    private static final String OWNED_IN_OTHER_TENANT = OWNED_IN_OTHER_TENANT_ID.value().toString();
    private static final String MISSING_DOCUMENT = "55555555-5555-5555-5555-555555555555";
    private static final String OTHER_OWNER = "someone-else";
    private static final String UNMATCHED_ROUTE = "/api/not-a-mapped-route";
    // An organization header a client may try to supply. Authorization never reads it — org comes
    // from the trusted profile and the resource — so these tests send it only to prove it is ignored.
    private static final String UNTRUSTED_ORG_HEADER = "X-Org-Id";
    private static final String ERROR_JSON_PATH = "$.error";
    private static final String FORBIDDEN_ERROR = "forbidden";
    private static final String HEALTH_STATUS_JSON_PATH = "$." + HealthRoutes.STATUS_FIELD;

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void postgresProperties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> RUNTIME_USERNAME);
        registry.add("spring.datasource.password", () -> DEV_PASSWORD);
        registry.add("showcase.demo-identity", () -> "true");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CapturingAuditSink auditSink;

    @Autowired
    private DocumentDirectory documents;

    @BeforeEach
    void resetState() throws Exception {
        auditSink.clear();
        try (Connection c = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement()) {
            st.execute("TRUNCATE TABLE " + DOCUMENT_TABLE);
            seed(c, OWNED_BY_MEMBER_ID, DocumentDirectory.ACME, DemoAccounts.MEMBER_USERNAME);
            seed(c, OWNED_BY_OTHER_ID, DocumentDirectory.ACME, OTHER_OWNER);
            seed(c, OWNED_IN_OTHER_TENANT_ID, OTHER_TENANT, OTHER_OWNER);
        }
    }

    private static void seed(final Connection c, final ResourceId id, final TenantId tenantId, final String owner)
        throws Exception {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO document (id, tenant_id, organization_id, owner_principal_type, owner_principal_key)"
                    + " VALUES (?, ?, ?, ?, ?)")) {
            ps.setObject(1, id.value());
            ps.setObject(2, tenantId.value());
            ps.setObject(3, DocumentDirectory.ENGINEERING.value());
            ps.setString(4, PrincipalType.USER.name());
            ps.setString(5, owner);
            ps.executeUpdate();
        }
    }

    private static String rawDemoPassword() {
        return DemoAccounts.PASSWORD.substring("{noop}".length());
    }

    @TestConfiguration
    static class AuditTestConfig {

        @Bean
        @Primary
        CapturingAuditSink capturingAuditSink() {
            return new CapturingAuditSink();
        }
    }

    @Test
    void unauthenticatedRequestIsRejected() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER).header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void nonCanonicalDocumentIdIsRejectedBeforeItCanNormalizeToAnotherUuid() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, "1-1-1-1-1")
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isBadRequest());
    }

    @Test
    void nonCanonicalTenantHeaderIsRejectedBeforeTenantComparison() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, "1-1-1-1-1"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void duplicateTenantHeadersAreRejectedRatherThanChoosingOneBoundaryClaim() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME, GLOBEX))
            .andExpect(status().isBadRequest());
    }

    @Test
    void anUnmatchedRouteIsDeniedByDefaultEvenWhenAuthenticated() throws Exception {
        mockMvc.perform(get(UNMATCHED_ROUTE).with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER)))
            .andExpect(status().isForbidden());
    }

    @Test
    void publicHealthOnlyPermitsGet() throws Exception {
        mockMvc.perform(post(HealthRoutes.HEALTH_PATH).with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER)))
            .andExpect(status().isForbidden());
    }

    @Test
    void publicHealthGetIsAllowedWithoutAuthentication() throws Exception {
        mockMvc.perform(get(HealthRoutes.HEALTH_PATH))
            .andExpect(status().isOk())
            .andExpect(jsonPath(HEALTH_STATUS_JSON_PATH).value(HealthRoutes.UP_STATUS));
    }

    @Test
    void basicAuthenticatedRequestDoesNotMintASessionCookie() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(httpBasic(DemoAccounts.MEMBER_USERNAME, rawDemoPassword()))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist("Set-Cookie"));
    }

    @Test
    void memberReadingTheirOwnDocumentIsAllowed() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isOk());
    }

    @Test
    void adminReadingAnyDocumentIsAllowedAsWideScope() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.ADMIN_USERNAME).roles(Roles.PLATFORM_ADMIN))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isOk());
    }

    @Test
    void adminReadingWithAnOrganizationHeaderIsAllowedAsWideScope() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.ADMIN_USERNAME).roles(Roles.PLATFORM_ADMIN))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isOk());
    }

    @Test
    void readingADocumentDoesNotExposeTheOwnerPrincipalKey() throws Exception {
        // A member may read a co-organization document they do not own, but the response must not
        // disclose the owner's principal key (an internal identity-provider subject).
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.resourceId.value").value(OWNED_BY_OTHER))
            .andExpect(jsonPath("$.ownerPrincipalKey").doesNotExist());
    }

    @Test
    void postgres18MintsVersion7DocumentIds() {
        final ProtectedResource created = documents.create(
            DocumentDirectory.ACME, DocumentDirectory.ENGINEERING, PrincipalType.USER, DemoAccounts.MEMBER_USERNAME);

        assertThat(created.resourceId().value().version()).isEqualTo(7);
    }

    @Test
    void missingDocumentReturnsNotFoundForTrustedInTenantActor() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, MISSING_DOCUMENT)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isNotFound());

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.RESOURCE_NOT_FOUND));
        assertThat(record.tenantId()).isEqualTo(DocumentDirectory.ACME);
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId().value().toString()).isEqualTo(MISSING_DOCUMENT);
        assertThat(record.resourceOrganizationId()).isNull();
    }

    @Test
    void aDocumentInAnotherTenantIsNotFoundRatherThanForbidden() throws Exception {
        // Cross-tenant existence is not leaked: a trusted ACME actor probing an id that lives in another
        // tenant gets 404 — the same response a truly-missing id produces — never a 403 that would
        // confirm the resource exists somewhere else.
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_IN_OTHER_TENANT)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isNotFound());

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.RESOURCE_NOT_FOUND));
        assertThat(record.tenantId()).isEqualTo(DocumentDirectory.ACME);
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId()).isEqualTo(OWNED_IN_OTHER_TENANT_ID);
        assertThat(record.resourceOrganizationId()).isNull();
    }

    @Test
    void readingWithAMismatchedTenantIsForbidden() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, GLOBEX)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath(ERROR_JSON_PATH).value(FORBIDDEN_ERROR));

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.TENANT_MISMATCH));
        assertThat(record.tenantId()).isEqualTo(DocumentDirectory.ACME);
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId()).isEqualTo(OWNED_BY_MEMBER_ID);
    }

    @Test
    void mismatchedTenantIsForbiddenBeforeMissingDocumentCanReturnNotFound() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, MISSING_DOCUMENT)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, GLOBEX)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath(ERROR_JSON_PATH).value(FORBIDDEN_ERROR));

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.TENANT_MISMATCH));
        assertThat(record.tenantId()).isEqualTo(DocumentDirectory.ACME);
        assertThat(record.resourceId().value().toString()).isEqualTo(MISSING_DOCUMENT);
        assertThat(record.resourceOrganizationId()).isNull();
    }

    @Test
    void aMismatchedOrganizationHeaderIsNonAuthoritativeAndAccessFollowsTheTrustedProfile() throws Exception {
        // The member is an ENGINEERING member reading an ENGINEERING document. A spoofed X-Org-Id (SALES)
        // is not an authorization input: it can neither grant nor revoke. The resource-aware decision
        // follows the trusted profile, so the in-organization read is allowed as an organization member.
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, SALES))
            .andExpect(status().isOk());

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId()).isEqualTo(OWNED_BY_OTHER_ID);
    }

    @Test
    void coarseMemberRoleWithoutTrustedActorProfileDoesNotCreateMembership() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.MALICIOUS_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath(ERROR_JSON_PATH).value(FORBIDDEN_ERROR));

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.principalKey()).isEqualTo(DemoAccounts.MALICIOUS_USERNAME);
        assertThat(record.tenantId()).isNull();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
        assertThat(record.resourceId()).isEqualTo(OWNED_BY_OTHER_ID);
    }

    @Test
    void untrustedActorProfileIsForbiddenBeforeMissingDocumentCanReturnNotFound() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, MISSING_DOCUMENT)
                .with(user(DemoAccounts.MALICIOUS_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath(ERROR_JSON_PATH).value(FORBIDDEN_ERROR));

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.principalKey()).isEqualTo(DemoAccounts.MALICIOUS_USERNAME);
        assertThat(record.tenantId()).isNull();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
        assertThat(record.resourceId().value().toString()).isEqualTo(MISSING_DOCUMENT);
        assertThat(record.resourceOrganizationId()).isNull();
    }

    @Test
    void aServiceCallerIsAuditedAsAServicePrincipalKeyedByClientId() throws Exception {
        // A non-interactive caller carrying the service marker is resolved to a ServicePrincipal at
        // the boundary, so the audit record names it by client id and principal type SERVICE — not a
        // UserPrincipal with a fabricated email. It has no trusted profile, so it is denied; the point
        // is the principal kind on the audit trail, not the outcome.
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.SERVICE_USERNAME)
                    .authorities(
                        new SimpleGrantedAuthority("ROLE_" + Roles.MEMBER),
                        new SimpleGrantedAuthority(RequestContextResolver.SERVICE_CALLER_AUTHORITY)))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isForbidden());

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.principalType()).isEqualTo(PrincipalType.SERVICE);
        assertThat(record.principalKey()).isEqualTo(DemoAccounts.SERVICE_USERNAME);
    }

    @Test
    void aServiceCallerNamedLikeDemoAdminDoesNotInheritTheUserAdminProfile() throws Exception {
        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.ADMIN_USERNAME)
                    .authorities(
                        new SimpleGrantedAuthority("ROLE_" + Roles.PLATFORM_ADMIN),
                        new SimpleGrantedAuthority(RequestContextResolver.SERVICE_CALLER_AUTHORITY)))
                .header(RequestHeaders.TENANT_ID, ACME))
            .andExpect(status().isForbidden());

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.principalType()).isEqualTo(PrincipalType.SERVICE);
        assertThat(record.principalKey()).isEqualTo(DemoAccounts.ADMIN_USERNAME);
        assertThat(record.tenantId()).isNull();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void memberDeletingTheirOwnDocumentRemovesIt() throws Exception {
        mockMvc.perform(delete(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isNoContent());

        mockMvc.perform(get(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isNotFound());
    }

    @Test
    void memberDeletingTheirOwnDocumentWithAMismatchedOrganizationHeaderIsAllowed() throws Exception {
        // Ownership is independent of organization membership: a non-matching X-Org-Id boundary hint
        // must not deny the resource owner. The resource-aware decision is made from the trusted
        // profile and the resource, not from the header.
        mockMvc.perform(delete(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_MEMBER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, SALES))
            .andExpect(status().isNoContent());
    }

    @Test
    void memberDeletingADocumentTheyDoNotOwnIsForbidden() throws Exception {
        mockMvc.perform(delete(DocumentRoutes.DOCUMENT_ID_ROUTE, OWNED_BY_OTHER)
                .with(user(DemoAccounts.MEMBER_USERNAME).roles(Roles.MEMBER))
                .header(RequestHeaders.TENANT_ID, ACME)
                .header(UNTRUSTED_ORG_HEADER, ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath(ERROR_JSON_PATH).value(FORBIDDEN_ERROR));

        // The generic body carries no reason; the specific reason is still captured on the audit path.
        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.outcome()).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
        assertThat(record.resourceId()).isEqualTo(OWNED_BY_OTHER_ID);
    }
}
