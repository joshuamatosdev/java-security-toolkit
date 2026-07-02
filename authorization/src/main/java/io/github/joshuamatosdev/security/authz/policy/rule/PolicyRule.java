package io.github.joshuamatosdev.security.authz.policy.rule;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyEffect;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;

import java.util.Objects;

/**
 * One rule in the effective policy: at {@code scopeType}, holding {@code roleKey} has {@code effect}
 * (ALLOW or DENY) for {@code action}. A rule is a <em>template</em> — it does not name a specific
 * organization; the concrete organization is supplied when the rule is matched against the actor's
 * {@link RoleAssignment}s and the resource's organization (see {@link EffectivePolicy}).
 *
 * <p>Changing what a role may do is a change to this rule set — data, not code.
 *
 * <p>Why this exists: policy rules keep role-to-action grants data-shaped so deny-overrides
 * behavior can change without controller rewrites.
 */
public record PolicyRule(String roleKey, Action action, PolicyEffect effect, PolicyScopeType scopeType) {

    public PolicyRule {
        roleKey = requireNonBlank(roleKey);
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(effect, "effect must not be null");
        Objects.requireNonNull(scopeType, "scopeType must not be null");
    }

    public static PolicyRule allow(final String roleKey, final Action action, final PolicyScopeType scopeType) {
        return new PolicyRule(roleKey, action, PolicyEffect.ALLOW, scopeType);
    }

    public static PolicyRule deny(final String roleKey, final Action action, final PolicyScopeType scopeType) {
        return new PolicyRule(roleKey, action, PolicyEffect.DENY, scopeType);
    }

    private static String requireNonBlank(final String value) {
        return RequiredText.require(value, "roleKey");
    }
}
