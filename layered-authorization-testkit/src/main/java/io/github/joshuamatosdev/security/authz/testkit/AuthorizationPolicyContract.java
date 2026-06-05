package io.github.joshuamatosdev.security.authz.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyEffect;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for resource-aware authorization policies. */
public interface AuthorizationPolicyContract {

    /** Policy under test. */
    AuthorizationPolicy policy();

    default TenantId tenant() {
        return TenantId.fromString("0190a000-0000-7000-8000-0000000000a1");
    }

    default TenantId otherTenant() {
        return TenantId.fromString("0190a000-0000-7000-8000-0000000000b2");
    }

    default OrganizationId organization() {
        return OrganizationId.fromString("0190a000-0000-7000-8000-0000000000d4");
    }

    @Test
    default void tenantMismatchDeniesBeforeGrants() {
        final RequestContext actor = new RequestContext(
                new UserPrincipal("user-1", "user@example.test", 0),
                tenant(),
                organization(),
                Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)),
                UUID.fromString("0190a000-0000-7000-8000-0000000000f6"));
        final ProtectedResource resource = new ProtectedResource(
                ResourceId.fromString("0190a000-0000-7000-8000-0000000000e5"),
                otherTenant(),
                organization(),
                "user-1");

        final Decision decision = policy().decide(actor, resource, Action.READ, new EffectivePolicy(List.of()));

        assertThat(decision).isEqualTo(new Deny(DenialReason.TENANT_MISMATCH));
    }

    @Test
    default void explicitDenyOverridesTenantWideAllow() {
        final RequestContext actor = new RequestContext(
                new UserPrincipal("user-1", "user@example.test", 0),
                tenant(),
                organization(),
                Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)),
                UUID.fromString("0190a000-0000-7000-8000-0000000000f6"));
        final ProtectedResource resource = new ProtectedResource(
                ResourceId.fromString("0190a000-0000-7000-8000-0000000000e5"),
                tenant(),
                organization(),
                "user-1");
        final EffectivePolicy effectivePolicy = new EffectivePolicy(List.of(
                new PolicyRule(Roles.PLATFORM_ADMIN, Action.DELETE, PolicyEffect.DENY, PolicyScopeType.TENANT)));

        final Decision decision = policy().decide(actor, resource, Action.DELETE, effectivePolicy);

        assertThat(decision).isEqualTo(new Deny(DenialReason.EXPLICIT_DENY));
    }
}
