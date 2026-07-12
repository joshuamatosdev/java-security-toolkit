package example.service;

import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Builds the immutable {@link RequestContext} once per request, from the <em>verified</em> JWT
 * alone — the same trust rule the tenant binding follows: no request header participates.
 *
 * <p>Claim contract (minted by the identity provider, relayed by the BFF):
 *
 * <ul>
 *   <li>{@code sub} — the principal key
 *   <li>{@code tenant_id} — the actor's tenant (required; the binding filter already rejected
 *       tokens without it)
 *   <li>{@code organization_id} — the actor's organization, optional
 *   <li>{@code roles} — bare role names; {@code PLATFORM_ADMIN} becomes a tenant-wide assignment,
 *       {@code MEMBER} an organization assignment when the token carries an organization, else a
 *       tenant-scoped one
 * </ul>
 *
 * <p>Showcase simplification: a production resolver loads the actor's scoped assignments from an
 * authorization store keyed on {@code sub}; deriving them from token claims keeps this example
 * self-contained while preserving the boundary that matters — claims are verified issuer
 * statements, not caller-writable headers.
 */
final class RequestContexts {

    private static final String EMAIL_CLAIM = "email";
    private static final String TENANT_CLAIM = "tenant_id";
    private static final String ORGANIZATION_CLAIM = "organization_id";
    private static final String ROLES_CLAIM = "roles";
    private static final long AUTHORIZATION_VERSION = 1L;

    private RequestContexts() {}

    static RequestContext fromJwt(final JwtAuthenticationToken authentication) {
        final Jwt jwt = authentication.getToken();
        final String subject = jwt.getSubject();
        final String email = jwt.getClaimAsString(EMAIL_CLAIM);
        final TenantId tenant = TenantId.fromString(jwt.getClaimAsString(TENANT_CLAIM));
        final String organizationClaim = jwt.getClaimAsString(ORGANIZATION_CLAIM);
        final OrganizationId organization =
                organizationClaim == null ? null : OrganizationId.fromString(organizationClaim);
        return new RequestContext(
                new UserPrincipal(subject, email == null ? subject + "@example.test" : email, AUTHORIZATION_VERSION),
                tenant,
                organization,
                assignments(jwt, organization),
                UUID.randomUUID());
    }

    private static Set<RoleAssignment> assignments(final Jwt jwt, final OrganizationId organization) {
        final var roles = jwt.getClaimAsStringList(ROLES_CLAIM);
        if (roles == null) {
            return Set.of();
        }
        return roles.stream()
                .map(role -> assignment(role, organization))
                .flatMap(Optional::stream)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static Optional<RoleAssignment> assignment(
            final String role,
            final OrganizationId organization) {
        if (Roles.PLATFORM_ADMIN.equals(role)) {
            return Optional.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN));
        }
        if (Roles.MEMBER.equals(role)) {
            return Optional.of(organization == null
                    ? RoleAssignment.tenant(Roles.MEMBER)
                    : RoleAssignment.organization(Roles.MEMBER, organization));
        }
        return Optional.empty();
    }
}
