package example.service;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The only tenant code this application owns — identical to the tenant-isolation walkthrough's
 * filter.
 *
 * <p>Resolves the tenant — and, when present, the organization — from the <em>verified</em> JWT,
 * never from a client-writable header, and binds both atomically around the rest of the request.
 * Boot registers this unordered filter bean after the Spring Security chain, so the authenticated
 * token is already in the {@link SecurityContextHolder} when it runs.
 *
 * <p>Unauthenticated or non-JWT requests carry no tenant to bind. Passing them through is safe: a
 * connection borrow with no binding fails closed before any SQL runs.
 */
@Component
class TenantBindingFilter extends OncePerRequestFilter {

    private final TenantContext tenantContext;

    TenantBindingFilter(final TenantContext tenantContext) {
        this.tenantContext = tenantContext;
    }

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
            throws ServletException, IOException {
        if (!(SecurityContextHolder.getContext().getAuthentication()
                instanceof JwtAuthenticationToken jwtAuthentication)) {
            chain.doFilter(request, response);
            return;
        }
        final Jwt jwt = jwtAuthentication.getToken();
        final String tenantClaim = jwt.getClaimAsString("tenant_id");
        if (tenantClaim == null) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        final TenantId tenant = TenantId.fromString(tenantClaim);
        final String organizationClaim = jwt.getClaimAsString("organization_id");
        final Runnable work = () -> {
            try {
                chain.doFilter(request, response);
            } catch (IOException | ServletException e) {
                throw new IllegalStateException(e);
            }
        };
        if (organizationClaim == null) {
            tenantContext.runAs(tenant, work);
        } else {
            tenantContext.runAs(tenant, OrganizationId.fromString(organizationClaim), work);
        }
    }
}
