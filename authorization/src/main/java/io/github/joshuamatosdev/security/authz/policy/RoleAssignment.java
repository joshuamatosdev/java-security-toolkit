package io.github.joshuamatosdev.security.authz.policy;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.shared.TeamId;
import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * A grant of a role to the actor <em>within a scope</em>. This is the membership fact that
 * role-only authorization is missing: not "is a member" but "is a member <em>of this
 * organization</em>" — or, narrower still, "of this team".
 *
 * <ul>
 *   <li>{@code TENANT} scope — {@code scopeId} and {@code teamScopeId} are {@code null}; the role
 *       is held tenant-wide.
 *   <li>{@code ORGANIZATION} scope — {@code scopeId} is the organization the role is held in;
 *       {@code teamScopeId} is {@code null}.
 *   <li>{@code TEAM} scope — {@code teamScopeId} is the team the role is held in and
 *       {@code scopeId} is that team's organization. A team never stands alone: carrying the
 *       organization in the assignment means a team grant can never match outside its
 *       organization, even if a team identifier were ever reused across organizations.
 * </ul>
 *
 * <p>Why this exists: the policy vocabulary names actions, effects, roles, and scopes once so
 * route and resource checks use the same language.
 */
public record RoleAssignment(
    String roleKey, PolicyScopeType scopeType, @Nullable OrganizationId scopeId, @Nullable TeamId teamScopeId) {

    public RoleAssignment {
        roleKey = requireNonBlank(roleKey);
        Objects.requireNonNull(scopeType, "scopeType must not be null");
        if (scopeType == PolicyScopeType.ORGANIZATION && scopeId == null) {
            throw new IllegalArgumentException("an ORGANIZATION-scoped assignment requires a scopeId");
        }
        if (scopeType == PolicyScopeType.TENANT && scopeId != null) {
            throw new IllegalArgumentException("a TENANT-scoped assignment must not carry a scopeId");
        }
        if (scopeType == PolicyScopeType.TEAM && (scopeId == null || teamScopeId == null)) {
            throw new IllegalArgumentException(
                "a TEAM-scoped assignment requires both its organization scopeId and its teamScopeId");
        }
        if (scopeType != PolicyScopeType.TEAM && teamScopeId != null) {
            throw new IllegalArgumentException("only a TEAM-scoped assignment may carry a teamScopeId");
        }
    }

    /**
     * Tenant-wide assignment of {@code roleKey}.
     */
    public static RoleAssignment tenant(final String roleKey) {
        return new RoleAssignment(roleKey, PolicyScopeType.TENANT, null, null);
    }

    /**
     * Assignment of {@code roleKey} within one organization.
     */
    public static RoleAssignment organization(final String roleKey, final OrganizationId organization) {
        return new RoleAssignment(roleKey, PolicyScopeType.ORGANIZATION, organization, null);
    }

    /**
     * Assignment of {@code roleKey} within one team of one organization.
     */
    public static RoleAssignment team(final String roleKey, final OrganizationId organization, final TeamId team) {
        return new RoleAssignment(roleKey, PolicyScopeType.TEAM, organization, team);
    }

    private static String requireNonBlank(final String value) {
        return RequiredText.require(value, "roleKey");
    }
}
