package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;

import java.time.Clock;
import java.util.Objects;

/**
 * Orchestrates one decision: load the tenant's effective rules, run the pure {@link AuthorizationPolicy},
 * write the audit entry (allow or deny), then throw on a deny. The orchestrator holds the I/O and
 * side effects; the decision itself stays a pure function. A {@link Clock} is injected so the audit
 * timestamp is deterministic in tests.
 */
public final class DefaultAuthorizationService implements AuthorizationService {

    private final AuthorizationPolicy policy;
    private final PolicyRuleRepository policyRuleRepository;
    private final AuthorizationAuditSink auditSink;
    private final Clock clock;

    public DefaultAuthorizationService(
        final AuthorizationPolicy policy,
        final PolicyRuleRepository policyRuleRepository,
        final AuthorizationAuditSink auditSink,
        final Clock clock) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.policyRuleRepository = Objects.requireNonNull(policyRuleRepository, "policyRuleRepository must not be null");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public void enforce(final RequestContext actor, final ProtectedResource resource, final Action action) {
        final Decision decision = decide(actor, resource, action);
        if (decision instanceof Deny deny) {
            throw new AuthorizationDeniedException(deny.reason());
        }
    }

    @Override
    public Decision decide(final RequestContext actor, final ProtectedResource resource, final Action action) {
        Objects.requireNonNull(actor, "actor must not be null");
        Objects.requireNonNull(resource, "resource must not be null");
        Objects.requireNonNull(action, "action must not be null");

        final EffectivePolicy effectivePolicy = policyRuleRepository.effectivePolicyFor(actor.tenantId());
        final Decision decision = policy.decide(actor, resource, action, effectivePolicy);
        auditSink.record(AuthorizationAuditRecord.of(actor, resource, action, decision, clock.instant()));
        return decision;
    }
}
