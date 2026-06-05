package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * Coordinates document lookup with the fine-grained authorization boundary. Pre-lookup denials are
 * audited against the attempted resource id so missing-resource probes cannot bypass the audit path.
 *
 * <p>Why this exists: document web components provide the resource-backed endpoint used to
 * demonstrate route gates plus fine-grained policy.
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
        final ResourceId resourceId,
        final Authentication authentication,
        final TenantId tenantId) {
        final RequestContext context =
            boundaryAuthorizer.authorize(authentication, tenantId, resourceId, Action.READ);
        final ProtectedResource resource = resolveResource(context, resourceId, Action.READ);
        authorizationService.enforce(context, resource, Action.READ);
        return resource;
    }

    public ResponseEntity<Void> delete(
        final ResourceId resourceId,
        final Authentication authentication,
        final TenantId tenantId) {
        final RequestContext context =
            boundaryAuthorizer.authorize(authentication, tenantId, resourceId, Action.DELETE);
        final ProtectedResource resource = resolveResource(context, resourceId, Action.DELETE);
        authorizationService.enforce(context, resource, Action.DELETE);
        documents.delete(context.tenantId(), resourceId);
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
