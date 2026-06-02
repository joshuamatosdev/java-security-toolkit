package io.github.joshuamatosdev.security.authz.policy;

/**
 * An action a caller may attempt on a resource. The action is part of the authorization decision —
 * a rule that allows {@link #READ} is not a rule that allows {@link #DELETE}. Rules are keyed on
 * {@code (role, action, effect, scope)}, so per-action granularity is the default, not an add-on.
 */
public enum Action {
    READ,
    UPDATE,
    DELETE
}
