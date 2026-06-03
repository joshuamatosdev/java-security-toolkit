package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.shared.ResourceId;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Coordinates document lookup with the fine-grained authorization boundary. Pre-lookup denials are
 * audited against the attempted resource id so missing-resource probes cannot bypass the audit path.
 */
@Component
public class DocumentRequestHandler {

    private final AuthorizationService authorizationService;
    private final DocumentBoundaryAuthorizer boundaryAuthorizer;
    private final DocumentDirectory documents;

    public DocumentRequestHandler(
        final AuthorizationService authorizationService,
        final DocumentBoundaryAuthorizer boundaryAuthorizer,
        final DocumentDirectory documents) {
        this.authorizationService = authorizationService;
        this.boundaryAuthorizer = boundaryAuthorizer;
        this.documents = documents;
    }

    public ProtectedResource read(
        final UUID id,
        final Authentication authentication,
        final UUID tenantId) {
        final ResourceId resourceId = new ResourceId(id);
        final RequestContext context =
            boundaryAuthorizer.authorize(authentication, tenantId, resourceId, Action.READ);
        final ProtectedResource resource = resolveResource(context, resourceId, Action.READ);
        authorizationService.enforce(context, resource, Action.READ);
        return resource;
    }

    public ResponseEntity<Void> delete(
        final UUID id,
        final Authentication authentication,
        final UUID tenantId) {
        final ResourceId resourceId = new ResourceId(id);
        final RequestContext context =
            boundaryAuthorizer.authorize(authentication, tenantId, resourceId, Action.DELETE);
        final ProtectedResource resource = resolveResource(context, resourceId, Action.DELETE);
        authorizationService.enforce(context, resource, Action.DELETE);
        documents.delete(resourceId);
        return ResponseEntity.noContent().build();
    }

    private ProtectedResource resolveResource(
        final RequestContext context,
        final ResourceId id,
        final Action action) {
        // Tenant-scoped lookup: a resource in another tenant is indistinguishable from a missing one
        // (both 404), so the response never reveals cross-tenant existence.
        return documents
            .find(context.tenantId(), id)
            .orElseThrow(() -> {
                final ProtectedResource attemptedResource =
                    new ProtectedResource(id, context.tenantId(), null, null);
                authorizationService.auditDeny(
                    context,
                    attemptedResource,
                    action,
                    DenialReason.RESOURCE_NOT_FOUND);
                return new ResponseStatusException(HttpStatus.NOT_FOUND);
            });
    }
}
