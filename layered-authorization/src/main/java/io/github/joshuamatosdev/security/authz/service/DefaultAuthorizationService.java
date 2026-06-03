package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;

import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/**
 * Orchestrates one decision: load the tenant's effective rules, run the pure {@link AuthorizationPolicy},
 * write the audit entry (allow or deny), then throw on a deny. The orchestrator holds the I/O and
 * side effects; the decision itself stays a pure function. A {@link Clock} is injected so the audit
 * timestamp is deterministic in tests.
 */
public final class DefaultAuthorizationService implements AuthorizationService {

    private static final String ACTION_REQUIRED = "action must not be null";
    private static final String ACTOR_REQUIRED = "actor must not be null";
    private static final String REASON_REQUIRED = "reason must not be null";
    private static final String RESOURCE_REQUIRED = "resource must not be null";

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
        if (decision instanceof Deny(DenialReason reason)) {
            throw new AuthorizationDeniedException(reason);
        }
    }

    @Override
    public Decision decide(final RequestContext actor, final ProtectedResource resource, final Action action) {
        Objects.requireNonNull(actor, ACTOR_REQUIRED);
        Objects.requireNonNull(resource, RESOURCE_REQUIRED);
        Objects.requireNonNull(action, ACTION_REQUIRED);

        final EffectivePolicy effectivePolicy = policyRuleRepository.effectivePolicyFor(actor.tenantId());
        final Decision decision = policy.decide(actor, resource, action, effectivePolicy);
        record(actor, resource, action, decision);
        return decision;
    }

    @Override
    public void deny(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final DenialReason reason) {
        Objects.requireNonNull(reason, REASON_REQUIRED);
        auditDeny(actor, resource, action, reason);
        throw new AuthorizationDeniedException(reason);
    }

    @Override
    public void auditDeny(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final DenialReason reason) {
        Objects.requireNonNull(reason, REASON_REQUIRED);
        record(actor, resource, action, new Deny(reason));
    }

    @Override
    public void denyWithoutTrustedContext(
        final PolicyPrincipal principal,
        final UUID correlationId,
        final ProtectedResource resource,
        final Action action,
        final DenialReason reason) {
        Objects.requireNonNull(principal, "principal must not be null");
        Objects.requireNonNull(correlationId, "correlationId must not be null");
        Objects.requireNonNull(resource, RESOURCE_REQUIRED);
        Objects.requireNonNull(action, ACTION_REQUIRED);
        Objects.requireNonNull(reason, REASON_REQUIRED);
        auditSink.record(AuthorizationAuditRecord.boundaryDenyWithoutTrustedContext(
            principal, correlationId, resource, action, reason, clock.instant()));
        throw new AuthorizationDeniedException(reason);
    }

    private void record(
        final RequestContext actor,
        final ProtectedResource resource,
        final Action action,
        final Decision decision) {
        Objects.requireNonNull(actor, ACTOR_REQUIRED);
        Objects.requireNonNull(resource, RESOURCE_REQUIRED);
        Objects.requireNonNull(action, ACTION_REQUIRED);
        Objects.requireNonNull(decision, "decision must not be null");
        auditSink.record(AuthorizationAuditRecord.of(actor, resource, action, decision, clock.instant()));
    }
}
