package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.web.config.SecurityConfig;
import io.github.joshuamatosdev.security.authz.web.support.RequestHeaders;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

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
 *
 * <p>Why this exists: document web components provide the resource-backed endpoint used to
 * demonstrate route gates plus fine-grained policy.
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
        @PathVariable final String id,
        final Authentication authentication,
        @RequestHeader(RequestHeaders.TENANT_ID) final String tenantId) {
        return DocumentResponse.from(
            documents.read(resourceId(id), authentication, tenantId(tenantId)));
    }

    @DeleteMapping(DocumentRoutes.DOCUMENT_ID_PATH)
    public ResponseEntity<Void> delete(
        @PathVariable final String id,
        final Authentication authentication,
        @RequestHeader(RequestHeaders.TENANT_ID) final String tenantId) {
        return documents.delete(resourceId(id), authentication, tenantId(tenantId));
    }

    private static ResourceId resourceId(final String raw) {
        try {
            return ResourceId.fromString(raw);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "document id must be a canonical UUID", ex);
        }
    }

    private static TenantId tenantId(final String raw) {
        try {
            return TenantId.fromString(raw);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenant id must be a canonical UUID", ex);
        }
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
