package io.github.joshuamatosdev.security.authz.policy.rule;

import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyEffect;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The set of {@link PolicyRule}s in force for a tenant, evaluated with the <strong>deny-overrides</strong>
 * algorithm. A rule matches the actor when, for the requested {@link Action}, the actor holds a
 * {@link RoleAssignment} with the rule's role key at the rule's scope — and, for an
 * {@code ORGANIZATION}-scoped rule, that assignment is in the <em>resource's</em> organization.
 *
 * <p>This is what distinguishes resource-aware authorization from role-only checks: the same role
 * grants different access depending on whether it is held tenant-wide or only inside the owning
 * organization, and per action.
 *
 * <p>Why this exists: policy rules keep role-to-action grants data-shaped so deny-overrides
 * behavior can change without controller rewrites.
 */
public final class EffectivePolicy {

    private final List<PolicyRule> rules;

    public EffectivePolicy(final List<PolicyRule> rules) {
        Objects.requireNonNull(rules, "rules must not be null");
        this.rules = List.copyOf(rules);
    }

    private static boolean assignmentSatisfies(
        final PolicyRule rule, final Set<RoleAssignment> assignments, @Nullable final OrganizationId resourceOrg) {
        return assignments.stream().anyMatch(assignment -> {
            if (!assignment.roleKey().equals(rule.roleKey()) || assignment.scopeType() != rule.scopeType()) {
                return false;
            }
            // An organization-scoped grant only counts for a resource in that same organization.
            if (rule.scopeType() == PolicyScopeType.ORGANIZATION) {
                return resourceOrg != null && resourceOrg.equals(assignment.scopeId());
            }
            return true;
        });
    }

    /**
     * True if any {@code DENY} rule matches the actor for this action; deny overrides every allow.
     */
    public boolean denies(
        final Set<RoleAssignment> assignments, @Nullable final OrganizationId resourceOrg, final Action action) {
        return anyMatch(PolicyEffect.DENY, assignments, resourceOrg, action).isPresent();
    }

    /**
     * The scope of a matching {@code ALLOW} rule, if any. Organization-scoped allows are reported
     * ahead of tenant-scoped allows, so the grant basis reflects the most specific scope that
     * permitted the action (organization membership before a tenant-wide effective permission).
     */
    public Optional<PolicyScopeType> allowingScope(
        final Set<RoleAssignment> assignments, @Nullable final OrganizationId resourceOrg, final Action action) {
        return anyMatch(PolicyEffect.ALLOW, assignments, resourceOrg, action);
    }

    private Optional<PolicyScopeType> anyMatch(
        final PolicyEffect effect,
        final Set<RoleAssignment> assignments,
        @Nullable final OrganizationId resourceOrg,
        final Action action) {
        // Organization scope first, then tenant scope, so a matched allow reports the most specific scope.
        for (final PolicyScopeType scope : List.of(PolicyScopeType.ORGANIZATION, PolicyScopeType.TENANT)) {
            final boolean matched = rules.stream()
                .filter(rule -> rule.effect() == effect)
                .filter(rule -> rule.action() == action)
                .filter(rule -> rule.scopeType() == scope)
                .anyMatch(rule -> assignmentSatisfies(rule, assignments, resourceOrg));
            if (matched) {
                return Optional.of(scope);
            }
        }
        return Optional.empty();
    }
}
