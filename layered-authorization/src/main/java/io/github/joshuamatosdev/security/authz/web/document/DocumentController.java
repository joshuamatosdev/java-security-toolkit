package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.web.config.SecurityConfig;
import io.github.joshuamatosdev.security.authz.web.support.RequestHeaders;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Demonstrates the two gates working together. The coarse request gate ({@link SecurityConfig}) has
 * already verified the caller holds {@code MEMBER} or {@code PLATFORM_ADMIN} to reach
 * {@code /api/documents/**}. The endpoint stays thin and delegates the resource-aware policy
 * flow to {@link DocumentRequestHandler}.
 *
 * <p>The verified tenant arrives as a header (as a gateway would inject it) and is cross-checked
 * against the resolved actor. The organization a caller may claim is not an authorization input:
 * organization membership comes from the trusted actor profile and the resource's own organization,
 * so a header can neither manufacture nor revoke access.
 */
@RestController
@RequestMapping(DocumentRoutes.DOCUMENTS_PATH)
public class DocumentController {

    private final DocumentRequestHandler documents;

    public DocumentController(final DocumentRequestHandler documents) {
        this.documents = documents;
    }

    @GetMapping(DocumentRoutes.DOCUMENT_ID_PATH)
    public DocumentResponse read(
        @PathVariable final UUID id,
        final Authentication authentication,
        @RequestHeader(RequestHeaders.TENANT_ID) final UUID tenantId) {
        return DocumentResponse.from(documents.read(id, authentication, tenantId));
    }

    @DeleteMapping(DocumentRoutes.DOCUMENT_ID_PATH)
    public ResponseEntity<Void> delete(
        @PathVariable final UUID id,
        final Authentication authentication,
        @RequestHeader(RequestHeaders.TENANT_ID) final UUID tenantId) {
        return documents.delete(id, authentication, tenantId);
    }

    /**
     * The client-facing projection of a document. It deliberately omits the owner's
     * {@link io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal#principalKey() principalKey}
     * — an internal identity-provider subject used only for the ownership decision — so reading a
     * document never discloses the owner's identity to other authorized readers.
     */
    public record DocumentResponse(
        ResourceId resourceId, TenantId tenantId, @Nullable OrganizationId organizationId) {

        static DocumentResponse from(final ProtectedResource resource) {
            return new DocumentResponse(resource.resourceId(), resource.tenantId(), resource.organizationId());
        }
    }
}
