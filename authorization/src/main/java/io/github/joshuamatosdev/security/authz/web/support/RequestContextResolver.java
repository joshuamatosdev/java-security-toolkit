package io.github.joshuamatosdev.security.authz.web.support;

import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.ServicePrincipal;
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
import java.util.Objects;
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
 *
 * <p>Why this exists: web support isolates header parsing, demo identity resolution, and exception
 * translation at the request boundary.
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

    /**
     * Authority that marks a non-interactive (machine) caller. A production auth layer attaches it to
     * client-credentials tokens; this resolver dispatches on it to build a {@link
     * io.github.joshuamatosdev.security.authz.principal.ServicePrincipal} rather than a user. It is
     * deliberately not {@code ROLE_}-prefixed, so it never enters {@link #roleKeys} as an
     * authorization role — it only selects the principal kind.
     */
    public static final String SERVICE_CALLER_AUTHORITY = "SERVICE_CALLER";

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String INVALID_PRINCIPAL_KEY = "invalid-principal";
    private static final String INVALID_PRINCIPAL_EMAIL = INVALID_PRINCIPAL_KEY + DemoAccounts.EMAIL_DOMAIN;

    private static Set<String> roleKeys(final Authentication authentication) {
        return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(Objects::nonNull)
            .filter(authority -> authority.startsWith(ROLE_PREFIX))
            .map(authority -> authority.substring(ROLE_PREFIX.length()))
            .collect(Collectors.toUnmodifiableSet());
    }

    private static boolean authoritiesCoverProfile(final TrustedActor actor, final Set<String> roles) {
        return actor.assignments().stream().map(RoleAssignment::roleKey).allMatch(roles::contains);
    }

    private static boolean isServiceCaller(final Authentication authentication) {
        return authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(SERVICE_CALLER_AUTHORITY::equals);
    }

    private static PolicyPrincipal principalFor(final String principalKey, final boolean serviceCaller) {
        if (serviceCaller) {
            // A machine caller is keyed by its client id (the authenticated name) and carries no email.
            return new ServicePrincipal(principalKey, 1L);
        }
        final String email =
            INVALID_PRINCIPAL_KEY.equals(principalKey)
                ? INVALID_PRINCIPAL_EMAIL
                : principalKey + DemoAccounts.EMAIL_DOMAIN;
        return new UserPrincipal(principalKey, email, 1L);
    }

    private static String safePrincipalKey(final String raw) {
        if (raw == null || raw.isBlank() || !raw.equals(raw.strip())
            || raw.chars().anyMatch(Character::isISOControl)) {
            return INVALID_PRINCIPAL_KEY;
        }
        return raw;
    }

    private static RequestContext contextFor(
        final PolicyPrincipal principal,
        final UUID correlationId,
        final TrustedActor actor) {
        return new RequestContext(principal, actor.tenantId(), actor.primaryOrganizationId(), actor.assignments(), correlationId);
    }

    public ResolvedRequestContext resolve(final Authentication authentication) {
        final boolean serviceCaller = isServiceCaller(authentication);
        final String principalKey = safePrincipalKey(authentication.getName());
        final PolicyPrincipal principal = principalFor(principalKey, serviceCaller);
        final UUID correlationId = UUID.randomUUID();
        final TrustedActor actor =
            demoIdentityEnabled && !serviceCaller ? TRUSTED_ACTORS.get(principalKey) : null;
        if (actor == null || !authoritiesCoverProfile(actor, roleKeys(authentication))) {
            return new ResolvedRequestContext(principal, correlationId, null);
        }
        return new ResolvedRequestContext(principal, correlationId, contextFor(principal, correlationId, actor));
    }
}
