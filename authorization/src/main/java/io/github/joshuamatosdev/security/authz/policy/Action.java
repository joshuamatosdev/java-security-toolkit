package io.github.joshuamatosdev.security.authz.policy;

/**
 * An action a caller may attempt on a resource. The action is part of the authorization decision —
 * a rule that allows {@link #READ} is not a rule that allows {@link #DELETE}. Rules are keyed on
 * {@code (role, action, effect, scope)}, so per-action granularity is the default, not an add-on.
 *
 * <p>Why this exists: the policy vocabulary names actions, effects, roles, and scopes once so
 * route and resource checks use the same language.
 */
public enum Action {
    READ,
    UPDATE,
    DELETE,
    /**
     * Authorizes bringing a resource into existence. The resource passed to the decision is the
     * prospective resource's placement (tenant, organization, owner-to-be) — creation is decided
     * against where the resource will live, since it does not exist yet. The owner grant applies
     * to {@code CREATE} like any other action: if the prospective owner is the caller itself,
     * creation is allowed as resource owner before any {@code CREATE} rule is consulted; a policy
     * that wants explicit {@code CREATE} rules to gate creation must not pre-assign the caller as
     * owner in the decision input. Appended after {@link #DELETE} so existing ordinals stay stable
     * for adopters who persisted them.
     */
    CREATE
}
