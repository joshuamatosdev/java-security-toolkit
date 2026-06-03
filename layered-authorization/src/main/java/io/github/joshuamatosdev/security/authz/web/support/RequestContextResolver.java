package io.github.joshuamatosdev.security.authz.web.support;

import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.web.document.DocumentDirectory;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Resolves the immutable {@link RequestContext} once, at the edge of the request, from the
 * authenticated {@link Authentication} plus the tenant/organization the gateway injects as headers.
 *
 * <p>Showcase simplification: a real resolver loads the actor's <em>scoped</em> role assignments from
 * the authorization store keyed on the subject. Here, to stay self-contained, each coarse authority
 * is resolved against a tiny trusted in-memory profile. The supplied tenant/organization headers are
 * boundary hints to validate, not authority to manufacture scoped membership. That follows the
 * tenant-isolation canon: caller-carried tenant values are transport/boundary claims, never the
 * authority that creates tenant context.
 *
 * <p>The in-memory trusted-actor seed is demo data gated behind {@code showcase.demo-identity=true}
 * (default off), so it can never grant a production identity by omission; a real deployment leaves the
 * flag off and resolves trusted actors from its authorization store.
 */
@Component
public class RequestContextResolver {

    private final boolean demoIdentityEnabled;

    public RequestContextResolver(
        @Value("${showcase.demo-identity:false}") final boolean demoIdentityEnabled) {
        this.demoIdentityEnabled = demoIdentityEnabled;
    }

    public record ResolvedRequestContext(
        PolicyPrincipal principal,
        UUID correlationId,
        @Nullable RequestContext trustedContext) {

        public boolean trustedProfile() {
            return trustedContext != null;
        }

        public RequestContext context() {
            if (trustedContext == null) {
                throw new IllegalStateException("trusted request context is not available");
            }
            return trustedContext;
        }
    }

    private record TrustedActor(
        TenantId tenantId, @Nullable OrganizationId primaryOrganizationId, Set<RoleAssignment> assignments) {
    }

    private static final Map<String, TrustedActor> TRUSTED_ACTORS = Map.of(
        DemoAccounts.MEMBER_USERNAME,
        new TrustedActor(
            DocumentDirectory.ACME,
            DocumentDirectory.ENGINEERING,
            Set.of(RoleAssignment.organization(Roles.MEMBER, DocumentDirectory.ENGINEERING))),
        DemoAccounts.ADMIN_USERNAME,
        new TrustedActor(
            DocumentDirectory.ACME,
            null,
            Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN))));

    private static final String ROLE_PREFIX = "ROLE_";

    private static Set<String> roleKeys(final Authentication authentication) {
        return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(authority -> authority.startsWith(ROLE_PREFIX))
            .map(authority -> authority.substring(ROLE_PREFIX.length()))
            .collect(Collectors.toUnmodifiableSet());
    }

    private static boolean authoritiesCoverProfile(final TrustedActor actor, final Set<String> roles) {
        return actor.assignments().stream().map(RoleAssignment::roleKey).allMatch(roles::contains);
    }

    private static PolicyPrincipal principalFor(final Authentication authentication) {
        return new UserPrincipal(authentication.getName(), authentication.getName() + DemoAccounts.EMAIL_DOMAIN, 1L);
    }

    private static RequestContext contextFor(
        final PolicyPrincipal principal,
        final UUID correlationId,
        final TrustedActor actor) {
        return new RequestContext(principal, actor.tenantId(), actor.primaryOrganizationId(), actor.assignments(), correlationId);
    }

    public ResolvedRequestContext resolve(final Authentication authentication) {
        final PolicyPrincipal principal = principalFor(authentication);
        final UUID correlationId = UUID.randomUUID();
        final TrustedActor actor = demoIdentityEnabled ? TRUSTED_ACTORS.get(authentication.getName()) : null;
        if (actor == null || !authoritiesCoverProfile(actor, roleKeys(authentication))) {
            return new ResolvedRequestContext(principal, correlationId, null);
        }
        return new ResolvedRequestContext(principal, correlationId, contextFor(principal, correlationId, actor));
    }
}
