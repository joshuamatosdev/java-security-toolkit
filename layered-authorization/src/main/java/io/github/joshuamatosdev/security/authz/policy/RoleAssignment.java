package io.github.joshuamatosdev.security.authz.policy;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * A grant of a role to the actor <em>within a scope</em>. This is the team/org fact that role-only
 * authorization is missing: not "is a member" but "is a member <em>of this organization</em>".
 *
 * <ul>
 *   <li>{@code TENANT} scope — {@code scopeId} is {@code null}; the role is held tenant-wide.
 *   <li>{@code ORGANIZATION} scope — {@code scopeId} is the organization the role is held in.
 * </ul>
 */
public record RoleAssignment(String roleKey, PolicyScopeType scopeType, @Nullable OrganizationId scopeId) {

    public RoleAssignment {
        Objects.requireNonNull(roleKey, "roleKey must not be null");
        Objects.requireNonNull(scopeType, "scopeType must not be null");
        if (scopeType == PolicyScopeType.ORGANIZATION && scopeId == null) {
            throw new IllegalArgumentException("an ORGANIZATION-scoped assignment requires a scopeId");
        }
        if (scopeType == PolicyScopeType.TENANT && scopeId != null) {
            throw new IllegalArgumentException("a TENANT-scoped assignment must not carry a scopeId");
        }
    }

    /**
     * Tenant-wide assignment of {@code roleKey}.
     */
    public static RoleAssignment tenant(final String roleKey) {
        return new RoleAssignment(roleKey, PolicyScopeType.TENANT, null);
    }

    /**
     * Assignment of {@code roleKey} within one organization.
     */
    public static RoleAssignment organization(final String roleKey, final OrganizationId organization) {
        return new RoleAssignment(roleKey, PolicyScopeType.ORGANIZATION, organization);
    }
}
