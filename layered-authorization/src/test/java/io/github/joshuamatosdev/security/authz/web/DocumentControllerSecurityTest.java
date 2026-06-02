package io.github.joshuamatosdev.security.authz.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Proves the two gates together over HTTP. The coarse request gate ({@link SecurityConfig}) enforces
 * authentication and deny-by-default at the route; the fine-grained {@code AuthorizationService}
 * decides resource access and surfaces a denial as 403. Tenant and organization arrive as the
 * headers a gateway would inject.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DocumentControllerSecurityTest {

    private static final String ACME = DocumentDirectory.ACME.value().toString();
    private static final String GLOBEX = "99999999-9999-9999-9999-999999999999";
    private static final String ENGINEERING = DocumentDirectory.ENGINEERING.value().toString();
    private static final String OWNED_BY_MEMBER = DocumentDirectory.OWNED_BY_MEMBER.value().toString();
    private static final String OWNED_BY_OTHER = DocumentDirectory.OWNED_BY_OTHER.value().toString();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void unauthenticatedRequestIsRejected() throws Exception {
        mockMvc.perform(get("/api/documents/{id}", OWNED_BY_MEMBER).header("X-Tenant-Id", ACME))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void anUnmatchedRouteIsDeniedByDefaultEvenWhenAuthenticated() throws Exception {
        mockMvc.perform(get("/api/not-a-mapped-route").with(user("member").roles("MEMBER")))
            .andExpect(status().isForbidden());
    }

    @Test
    void memberReadingTheirOwnDocumentIsAllowed() throws Exception {
        mockMvc.perform(get("/api/documents/{id}", OWNED_BY_MEMBER)
                .with(user("member").roles("MEMBER"))
                .header("X-Tenant-Id", ACME)
                .header("X-Org-Id", ENGINEERING))
            .andExpect(status().isOk());
    }

    @Test
    void adminReadingAnyDocumentIsAllowedAsWideScope() throws Exception {
        mockMvc.perform(get("/api/documents/{id}", OWNED_BY_OTHER)
                .with(user("admin").roles("PLATFORM_ADMIN"))
                .header("X-Tenant-Id", ACME))
            .andExpect(status().isOk());
    }

    @Test
    void readingWithAMismatchedTenantIsForbidden() throws Exception {
        mockMvc.perform(get("/api/documents/{id}", OWNED_BY_MEMBER)
                .with(user("member").roles("MEMBER"))
                .header("X-Tenant-Id", GLOBEX)
                .header("X-Org-Id", ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.denied").value("TENANT_MISMATCH"));
    }

    @Test
    void memberDeletingADocumentTheyDoNotOwnIsForbidden() throws Exception {
        mockMvc.perform(delete("/api/documents/{id}", OWNED_BY_OTHER)
                .with(user("member").roles("MEMBER"))
                .header("X-Tenant-Id", ACME)
                .header("X-Org-Id", ENGINEERING))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.denied").value("NO_MATCHING_RULE"));
    }
}
