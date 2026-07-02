package io.github.joshuamatosdev.security.authz.policy;

/**
 * The scope a role assignment or a policy rule applies within.
 *
 * <ul>
 *   <li>{@code TENANT} — tenant-wide: the assignment/rule applies to every resource in the tenant.
 *   <li>{@code ORGANIZATION} — scoped to one organization: an assignment grants the role only
 *       inside its organization, and an organization-scoped rule matches only when the actor holds
 *       that role in the <em>resource's</em> organization.
 *   <li>{@code TEAM} — scoped to one team within an organization: the narrowest grant. A
 *       team-scoped assignment counts only when the resource sits in the same organization
 *       <em>and</em> the same team. Teams are a discretionary grant boundary in this layer —
 *       grouping, not isolation; the data plane never sees them.
 * </ul>
 *
 * <p>Why this exists: the policy vocabulary names actions, effects, roles, and scopes once so
 * route and resource checks use the same language.
 */
public enum PolicyScopeType {
    TENANT,
    ORGANIZATION,
    /** Appended after {@link #ORGANIZATION} so existing ordinals stay stable for adopters who persisted them. */
    TEAM
}
