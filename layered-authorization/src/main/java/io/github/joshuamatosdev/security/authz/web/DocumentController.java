package io.github.joshuamatosdev.security.authz.web;

import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Demonstrates the two gates working together. The coarse request gate ({@link SecurityConfig}) has
 * already verified the caller holds {@code MEMBER} or {@code PLATFORM_ADMIN} to reach
 * {@code /api/documents/**}. This controller then makes the <em>fine-grained, resource-aware</em>
 * decision the gate cannot: it loads the document's facts and calls
 * {@link AuthorizationService#enforce}, which audits and throws on a deny.
 *
 * <p>The verified tenant and organization arrive as headers (as a gateway would inject them).
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final AuthorizationService authorizationService;
    private final RequestContextResolver requestContextResolver;
    private final DocumentDirectory documents;

    public DocumentController(
        final AuthorizationService authorizationService,
        final RequestContextResolver requestContextResolver,
        final DocumentDirectory documents) {
        this.authorizationService = authorizationService;
        this.requestContextResolver = requestContextResolver;
        this.documents = documents;
    }

    @GetMapping("/{id}")
    public ProtectedResource read(
        @PathVariable final UUID id,
        final Authentication authentication,
        @RequestHeader("X-Tenant-Id") final UUID tenantId,
        @RequestHeader(value = "X-Org-Id", required = false) @Nullable final UUID organizationId) {
        final ProtectedResource resource = resolveResource(id);
        authorize(authentication, tenantId, organizationId, resource, Action.READ);
        return resource;
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(
        @PathVariable final UUID id,
        final Authentication authentication,
        @RequestHeader("X-Tenant-Id") final UUID tenantId,
        @RequestHeader(value = "X-Org-Id", required = false) @Nullable final UUID organizationId) {
        final ProtectedResource resource = resolveResource(id);
        authorize(authentication, tenantId, organizationId, resource, Action.DELETE);
    }

    private ProtectedResource resolveResource(final UUID id) {
        return documents
            .find(new ResourceId(id))
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    private void authorize(
        final Authentication authentication,
        final UUID tenantId,
        @Nullable final UUID organizationId,
        final ProtectedResource resource,
        final Action action) {
        final OrganizationId organization = organizationId == null ? null : new OrganizationId(organizationId);
        final RequestContext context =
            requestContextResolver.resolve(authentication, new TenantId(tenantId), organization);
        authorizationService.enforce(context, resource, action);
    }
}
