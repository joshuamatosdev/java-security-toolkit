package io.github.joshuamatosdev.security.authz.request;

import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.jspecify.annotations.Nullable;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * The immutable per-request authorization facts about the <em>actor</em>, resolved once at the edge
 * of the request and then passed by parameter into the decision. A decision never reaches back into
 * a thread-local or re-parses a token — it is a pure function of this context (plus the resource and
 * the action).
 *
 * @param principal       the authenticated actor
 * @param tenantId        the actor's verified tenant — the outer authorization boundary
 * @param organizationId  the actor's primary organization, if any (may be {@code null})
 * @param roleAssignments the actor's scoped role grants (tenant-wide and/or per organization)
 * @param correlationId   ties every audit entry for this request together
 *
 * <p>Why this exists: request and resource facts are explicit policy inputs, which avoids
 * authorization decisions depending on mutable web framework state.
 */
public record RequestContext(
    PolicyPrincipal principal,
    TenantId tenantId,
    @Nullable OrganizationId organizationId,
    Set<RoleAssignment> roleAssignments,
    UUID correlationId) {

    public RequestContext {
        Objects.requireNonNull(principal, "principal must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(roleAssignments, "roleAssignments must not be null")
            .forEach(assignment -> Objects.requireNonNull(assignment, "roleAssignment must not be null"));
        roleAssignments = Set.copyOf(roleAssignments);
    }

    public String principalKey() {
        return principal.principalKey();
    }

    /**
     * True if the actor holds {@code roleKey} tenant-wide — the basis for the wide-scope admin short-circuit.
     */
    public boolean hasTenantScopedRole(final String roleKey) {
        return roleAssignments.stream()
            .anyMatch(a -> a.scopeType() == PolicyScopeType.TENANT && a.roleKey().equals(roleKey));
    }

    /**
     * True when the actor has any tenant-wide assignment.
     */
    public boolean hasTenantScopedAssignment() {
        return roleAssignments.stream().anyMatch(a -> a.scopeType() == PolicyScopeType.TENANT);
    }
}
