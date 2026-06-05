package io.github.joshuamatosdev.security.authz.policy;

/**
 * The scope a role assignment or a policy rule applies within.
 *
 * <ul>
 *   <li>{@code TENANT} — tenant-wide: the assignment/rule applies to every resource in the tenant.
 *   <li>{@code ORGANIZATION} — scoped to one organization (team): an assignment grants the role only
 *       inside its organization, and an organization-scoped rule matches only when the actor holds
 *       that role in the <em>resource's</em> organization.
 * </ul>
 *
 * <p>Why this exists: the policy vocabulary names actions, effects, roles, and scopes once so
 * route and resource checks use the same language.
 */
public enum PolicyScopeType {
    TENANT,
    ORGANIZATION
}
