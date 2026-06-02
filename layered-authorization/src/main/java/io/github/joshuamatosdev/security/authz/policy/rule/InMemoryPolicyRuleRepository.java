package io.github.joshuamatosdev.security.authz.policy.rule;

import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.shared.TenantId;

import java.util.List;

/**
 * A neutral, in-memory {@link PolicyRuleRepository} so the showcase needs no database. The seeded
 * rule set is a sane example policy:
 *
 * <ul>
 *   <li>a {@code MEMBER} of an organization may {@code READ} and {@code UPDATE} that organization's
 *       resources (organization-scoped);
 *   <li>a tenant-wide {@code MEMBER} may {@code READ} any resource in the tenant (a tenant-scoped
 *       effective permission);
 *   <li>no rule lets a {@code MEMBER} {@code DELETE} — only the resource owner or the wide-scope
 *       admin can, which is the per-action granularity the model is built for.
 * </ul>
 * <p>
 * The same rule set is returned for every tenant here; a real adapter would load the tenant's rows.
 */
public final class InMemoryPolicyRuleRepository implements PolicyRuleRepository {

    private static final EffectivePolicy POLICY = new EffectivePolicy(List.of(
        PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION),
        PolicyRule.allow(Roles.MEMBER, Action.UPDATE, PolicyScopeType.ORGANIZATION),
        PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TENANT)));

    @Override
    public EffectivePolicy effectivePolicyFor(final TenantId tenant) {
        return POLICY;
    }
}
