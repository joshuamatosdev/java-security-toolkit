package io.github.joshuamatosdev.security.authz.policy.rule;

import io.github.joshuamatosdev.security.shared.TenantId;

/**
 * Port that supplies the {@link EffectivePolicy} in force for a tenant. In production this reads the
 * {@code role_policy_rule} rows for the tenant; the decision layer depends only on this interface, so
 * the rule source (database, cache, config) is an adapter detail.
 */
public interface PolicyRuleRepository {

    EffectivePolicy effectivePolicyFor(TenantId tenant);
}
