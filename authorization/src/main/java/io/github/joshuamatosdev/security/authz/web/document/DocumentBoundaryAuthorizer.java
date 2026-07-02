package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.authz.web.support.RequestContextResolver;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Validates caller-carried boundary facts before document lookup. Denials stay on the
 * {@link AuthorizationService} audit path even when the actual resource has not been loaded yet.
 *
 * <p>Why this exists: document web components provide the resource-backed endpoint used to
 * demonstrate route gates plus fine-grained policy.
 */
@Component
public class DocumentBoundaryAuthorizer {

    private final AuthorizationService authorizationService;
    private final RequestContextResolver requestContextResolver;

    public DocumentBoundaryAuthorizer(
        final AuthorizationService authorizationService,
        final RequestContextResolver requestContextResolver) {
        this.authorizationService = authorizationService;
        this.requestContextResolver = requestContextResolver;
    }

    public RequestContext authorize(
        final Authentication authentication,
        final TenantId requestedTenant,
        final ResourceId resourceId,
        final Action action) {
        final ProtectedResource attemptedResource = new ProtectedResource(resourceId, requestedTenant, null, null);
        final RequestContextResolver.ResolvedRequestContext resolved =
            requestContextResolver.resolve(authentication);

        denyUntrustedProfile(resolved, attemptedResource, action);
        final RequestContext context = resolved.context();
        denyTenantMismatch(context, requestedTenant, attemptedResource, action);
        return context;
    }

    private void denyUntrustedProfile(
        final RequestContextResolver.ResolvedRequestContext resolved,
        final ProtectedResource attemptedResource,
        final Action action) {
        if (!resolved.trustedProfile()) {
            authorizationService.denyWithoutTrustedContext(
                resolved.principal(),
                resolved.correlationId(),
                attemptedResource,
                action,
                DenialReason.NO_MATCHING_RULE);
        }
    }

    private void denyTenantMismatch(
        final RequestContext context,
        final TenantId requestedTenant,
        final ProtectedResource attemptedResource,
        final Action action) {
        if (!context.tenantId().equals(requestedTenant)) {
            authorizationService.deny(context, attemptedResource, action, DenialReason.TENANT_MISMATCH);
        }
    }
}
