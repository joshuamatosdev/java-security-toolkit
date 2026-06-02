package io.github.joshuamatosdev.security.authz.policy;

import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;

/**
 * The effect of a {@link PolicyRule}. {@code DENY} overrides {@code ALLOW}: if any matching DENY
 * rule exists for an action, the action is denied regardless of how many ALLOW rules also match, so
 * a revocation is effective immediately and cannot be out-voted by a broad grant.
 */
public enum PolicyEffect {
    ALLOW,
    DENY
}
