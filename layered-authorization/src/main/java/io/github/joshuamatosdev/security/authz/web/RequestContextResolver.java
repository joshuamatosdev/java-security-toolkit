package io.github.joshuamatosdev.security.authz.web;

import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Resolves the immutable {@link RequestContext} once, at the edge of the request, from the
 * authenticated {@link Authentication} plus the tenant/organization the gateway injects as headers.
 *
 * <p>Showcase simplification: a real resolver loads the actor's <em>scoped</em> role assignments from
 * the authorization store keyed on the subject. Here, to stay self-contained, each coarse authority
 * is mapped to one assignment — {@code PLATFORM_ADMIN} tenant-wide (the wide-scope admin), any other
 * role within the supplied organization if one is present, else tenant-wide.
 */
@Component
public class RequestContextResolver {

    private static RoleAssignment toAssignment(final String role, @Nullable final OrganizationId organization) {
        if (Roles.PLATFORM_ADMIN.equals(role)) {
            return RoleAssignment.tenant(role);
        }
        return organization != null ? RoleAssignment.organization(role, organization) : RoleAssignment.tenant(role);
    }

    public RequestContext resolve(
        final Authentication authentication, final TenantId tenant, @Nullable final OrganizationId organization) {
        final PolicyPrincipal principal =
            new UserPrincipal(authentication.getName(), authentication.getName() + "@example.test", 1L);
        final Set<RoleAssignment> assignments = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(authority -> authority.startsWith("ROLE_"))
            .map(authority -> authority.substring("ROLE_".length()))
            .map(role -> toAssignment(role, organization))
            .collect(Collectors.toUnmodifiableSet());
        return new RequestContext(principal, tenant, organization, assignments, UUID.randomUUID());
    }
}
