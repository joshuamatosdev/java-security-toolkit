package io.github.joshuamatosdev.security.authz.spring;

import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.List;
import java.util.Objects;

/** Default rule source that grants no role-based permissions. */
final class DenyAllPolicyRuleRepository implements PolicyRuleRepository {

    private static final EffectivePolicy DENY_ALL = new EffectivePolicy(List.of());

    @Override
    public EffectivePolicy effectivePolicyFor(final TenantId tenant) {
        Objects.requireNonNull(tenant, "tenant");
        return DENY_ALL;
    }
}
