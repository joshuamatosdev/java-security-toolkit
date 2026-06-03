package io.github.joshuamatosdev.security.authz.policy;

import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;

/**
 * The effect of a {@link PolicyRule}. {@code DENY} overrides {@code ALLOW}: among the rules that match
 * the actor for an action, any matching DENY denies, regardless of how many ALLOW rules also match — a
 * matched revocation cannot be out-voted by a grant.
 *
 * <p><strong>Matching is scope-specific.</strong> A rule matches only an assignment held at the rule's
 * {@link PolicyScopeType} (see
 * {@link io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy}). A {@code TENANT}-scoped
 * DENY therefore revokes tenant-wide holders, not organization-scoped holders — mirroring the rule that
 * an organization-scoped grant is not tenant-wide access. To revoke a role across both scopes, author a
 * DENY at each scope.
 */
public enum PolicyEffect {
    ALLOW,
    DENY
}
