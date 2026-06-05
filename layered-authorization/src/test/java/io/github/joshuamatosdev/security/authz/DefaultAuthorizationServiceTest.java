package io.github.joshuamatosdev.security.authz;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditRecord;
import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.InMemoryPolicyRuleRepository;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationDeniedException;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import io.github.joshuamatosdev.security.authz.service.DefaultAuthorizationService;
import io.github.joshuamatosdev.security.authz.testfixtures.CapturingAuditSink;
import io.github.joshuamatosdev.security.authz.web.support.DemoAccounts;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Verifies the orchestrator's contract around the pure decision: every decision is recorded (allow
 * and deny), a deny is recorded <em>before</em> the guard throws, and a wide-scope admin allow is
 * flagged in the audit trail. Uses the real {@link AuthorizationPolicy} and
 * {@link InMemoryPolicyRuleRepository}; only the audit sink and clock are test doubles.
 *
 * <p>Why this is important to test: authorization is a privilege boundary, so the documented
 * route, policy, and audit contracts need executable proof.
 */
class DefaultAuthorizationServiceTest {

    private static final Instant FIXED = Instant.parse("2026-06-02T12:00:00Z");
    private static final TenantId ACME = new TenantId(UUID.fromString("11111111-1111-1111-1111-111111111111"));
    private static final OrganizationId ENGINEERING =
        new OrganizationId(UUID.fromString("22222222-2222-2222-2222-222222222222"));
    private static final ResourceId DOC = new ResourceId(UUID.fromString("33333333-3333-3333-3333-333333333333"));
    private static final String OTHER_OWNER = "someone-else";
    private static final String OWNER_SUBJECT = "alice";
    private static final String MEMBER_SUBJECT = "bob";

    private final CapturingAuditSink auditSink = new CapturingAuditSink();
    private final AuthorizationService service = new DefaultAuthorizationService(
        new AuthorizationPolicy(),
        new InMemoryPolicyRuleRepository(),
        auditSink,
        Clock.fixed(FIXED, ZoneOffset.UTC));

    private static RequestContext context(final Set<RoleAssignment> assignments, final String subject) {
        final OrganizationId org = assignments.stream()
            .anyMatch(a -> a.scopeType() == PolicyScopeType.ORGANIZATION)
            ? ENGINEERING
            : null;
        return new RequestContext(
            new UserPrincipal(subject, subject + DemoAccounts.EMAIL_DOMAIN, 1L), ACME, org, assignments, UUID.randomUUID());
    }

    @Test
    void anAllowedDecisionReturnsAndIsAuditedWithItsGrantBasisAndClockTimestamp() {
        final RequestContext owner = context(Set.of(), OWNER_SUBJECT);
        final ProtectedResource ownedByAlice = new ProtectedResource(DOC, ACME, ENGINEERING, OWNER_SUBJECT);

        service.enforce(owner, ownedByAlice, Action.DELETE);

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.allowed()).isTrue();
        assertThat(record.grantBasis()).isEqualTo(GrantBasis.RESOURCE_OWNER);
        assertThat(record.denialReason()).isNull();
        assertThat(record.wideScope()).isFalse();
        assertThat(record.at()).isEqualTo(FIXED);
        assertThat(record.action()).isEqualTo(Action.DELETE);
        assertThat(record.resourceId()).isEqualTo(DOC);
    }

    @Test
    void aDeniedDecisionIsAuditedAndThenThrows() {
        // A tenant-wide member cannot DELETE — no rule, not owner, not admin.
        final RequestContext member = context(Set.of(RoleAssignment.tenant(Roles.MEMBER)), MEMBER_SUBJECT);
        final ProtectedResource doc = new ProtectedResource(DOC, ACME, ENGINEERING, OTHER_OWNER);

        assertThatThrownBy(() -> service.enforce(member, doc, Action.DELETE))
            .isInstanceOf(AuthorizationDeniedException.class)
            .extracting(ex -> ((AuthorizationDeniedException) ex).reason())
            .isEqualTo(DenialReason.NO_MATCHING_RULE);

        // The deny was logged before the throw — a denial that is not recorded did not happen.
        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.allowed()).isFalse();
        assertThat(record.denialReason()).isEqualTo(DenialReason.NO_MATCHING_RULE);
        assertThat(record.grantBasis()).isNull();
    }

    @Test
    void aWideScopeAdminAllowIsFlaggedInTheAuditTrail() {
        final RequestContext admin = context(Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)), "ops");
        final ProtectedResource doc = new ProtectedResource(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = service.decide(admin, doc, Action.DELETE);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.WIDE_SCOPE_ADMIN));
        assertThat(auditSink.only().wideScope()).isTrue();
    }

    @Test
    void anAlreadyDeterminedBoundaryDenyIsAuditedAndThenThrows() {
        final RequestContext member = context(Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), MEMBER_SUBJECT);
        final ProtectedResource doc = new ProtectedResource(DOC, ACME, ENGINEERING, OTHER_OWNER);

        assertThatThrownBy(() -> service.deny(member, doc, Action.READ, DenialReason.TENANT_MISMATCH))
            .isInstanceOf(AuthorizationDeniedException.class)
            .extracting(ex -> ((AuthorizationDeniedException) ex).reason())
            .isEqualTo(DenialReason.TENANT_MISMATCH);

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.allowed()).isFalse();
        assertThat(record.denialReason()).isEqualTo(DenialReason.TENANT_MISMATCH);
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId()).isEqualTo(DOC);
    }

    @Test
    void anAlreadyDeterminedNonForbiddenDenyCanBeAuditedWithoutThrowing() {
        final RequestContext member = context(Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), MEMBER_SUBJECT);
        final ProtectedResource doc = new ProtectedResource(DOC, ACME, null, null);

        service.auditDeny(member, doc, Action.READ, DenialReason.RESOURCE_NOT_FOUND);

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.allowed()).isFalse();
        assertThat(record.denialReason()).isEqualTo(DenialReason.RESOURCE_NOT_FOUND);
        assertThat(record.action()).isEqualTo(Action.READ);
        assertThat(record.resourceId()).isEqualTo(DOC);
    }

    @Test
    void anUntrustedBoundaryDenyIsAuditedWithoutInventingTenantContext() {
        final UserPrincipal principal = new UserPrincipal(
            DemoAccounts.MALICIOUS_USERNAME,
            DemoAccounts.MALICIOUS_USERNAME + DemoAccounts.EMAIL_DOMAIN,
            1L);
        final UUID correlationId = UUID.randomUUID();
        final ProtectedResource doc = new ProtectedResource(DOC, ACME, ENGINEERING, OTHER_OWNER);

        assertThatThrownBy(() -> service.denyWithoutTrustedContext(
                principal, correlationId, doc, Action.READ, DenialReason.NO_MATCHING_RULE))
            .isInstanceOf(AuthorizationDeniedException.class)
            .extracting(ex -> ((AuthorizationDeniedException) ex).reason())
            .isEqualTo(DenialReason.NO_MATCHING_RULE);

        final AuthorizationAuditRecord record = auditSink.only();
        assertThat(record.principalKey()).isEqualTo(DemoAccounts.MALICIOUS_USERNAME);
        assertThat(record.tenantId()).isNull();
        assertThat(record.correlationId()).isEqualTo(correlationId);
        assertThat(record.denialReason()).isEqualTo(DenialReason.NO_MATCHING_RULE);
    }
}
