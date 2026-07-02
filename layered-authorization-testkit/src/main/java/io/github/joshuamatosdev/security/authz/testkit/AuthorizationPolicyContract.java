package io.github.joshuamatosdev.security.authz.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.authz.decision.Allow;
import io.github.joshuamatosdev.security.authz.decision.Decision;
import io.github.joshuamatosdev.security.authz.decision.DenialReason;
import io.github.joshuamatosdev.security.authz.decision.Deny;
import io.github.joshuamatosdev.security.authz.decision.GrantBasis;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyEffect;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TeamId;
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

    default OrganizationId otherOrganization() {
        return OrganizationId.fromString("0190a000-0000-7000-8000-0000000000c3");
    }

    default TeamId team() {
        return TeamId.fromString("0190a000-0000-7000-8000-0000000000a7");
    }

    default TeamId otherTeam() {
        return TeamId.fromString("0190a000-0000-7000-8000-0000000000b8");
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

    @Test
    default void deniesByDefaultWhenInTenantActorMatchesNoRule() {
        // The single most important fail-open guard: an in-tenant actor that is neither the owner nor
        // holds any granting role must end in deny-by-default, not an implicit permit.
        final Decision decision = policy().decide(
                memberActor(organization(), Set.of()),
                organizationResource(organization()),
                Action.READ,
                organizationMemberPolicy());

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    default void organizationMemberIsAllowedWithinTheirOrganization() {
        final Decision decision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.organization(Roles.MEMBER, organization()))),
                organizationResource(organization()),
                Action.READ,
                organizationMemberPolicy());

        assertThat(decision).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
    }

    @Test
    default void organizationMemberOfAnotherOrganizationIsDenied() {
        // Organization-scope isolation (the IDOR boundary): a member of one organization must not reach
        // a resource owned by another, even for an action their role permits in-organization.
        final Decision decision = policy().decide(
                memberActor(otherOrganization(), Set.of(RoleAssignment.organization(Roles.MEMBER, otherOrganization()))),
                organizationResource(organization()),
                Action.READ,
                organizationMemberPolicy());

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    default void organizationMemberIsDeniedForAnActionNoRulePermits() {
        final Decision decision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.organization(Roles.MEMBER, organization()))),
                organizationResource(organization()),
                Action.DELETE,
                organizationMemberPolicy());

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    default void teamMemberIsAllowedWithinTheirTeam() {
        final Decision decision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.team(Roles.MEMBER, organization(), team()))),
                teamResource(organization(), team()),
                Action.READ,
                teamMemberPolicy());

        assertThat(decision).isEqualTo(new Allow(GrantBasis.TEAM_MEMBER));
    }

    @Test
    default void teamScopedGrantIsIsolatedToItsTeam() {
        // Team-scope isolation: a team-scoped grant must reach neither another team's resources nor
        // team-unplaced resources of the same organization.
        final Decision otherTeamDecision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.team(Roles.MEMBER, organization(), team()))),
                teamResource(organization(), otherTeam()),
                Action.READ,
                teamMemberPolicy());
        final Decision teamlessDecision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.team(Roles.MEMBER, organization(), team()))),
                organizationResource(organization()),
                Action.READ,
                teamMemberPolicy());

        assertThat(otherTeamDecision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
        assertThat(teamlessDecision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    default void tenantScopedAdminIsAllowedAsWideScope() {
        final Decision decision = policy().decide(
                memberActor(organization(), Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN))),
                organizationResource(organization()),
                Action.DELETE,
                organizationMemberPolicy());

        assertThat(decision).isEqualTo(new Allow(GrantBasis.WIDE_SCOPE_ADMIN));
    }

    private RequestContext memberActor(final OrganizationId actorOrganization, final Set<RoleAssignment> assignments) {
        return new RequestContext(
                new UserPrincipal("user-1", "user@example.test", 0),
                tenant(),
                actorOrganization,
                assignments,
                UUID.fromString("0190a000-0000-7000-8000-0000000000f6"));
    }

    private ProtectedResource organizationResource(final OrganizationId resourceOrganization) {
        return new ProtectedResource(
                ResourceId.fromString("0190a000-0000-7000-8000-0000000000e5"),
                tenant(),
                resourceOrganization,
                "other-owner");
    }

    private ProtectedResource teamResource(final OrganizationId resourceOrganization, final TeamId resourceTeam) {
        return new ProtectedResource(
                ResourceId.fromString("0190a000-0000-7000-8000-0000000000e5"),
                tenant(),
                resourceOrganization,
                resourceTeam,
                PrincipalType.USER,
                "other-owner");
    }

    private static EffectivePolicy organizationMemberPolicy() {
        return new EffectivePolicy(List.of(
                PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION),
                PolicyRule.allow(Roles.MEMBER, Action.UPDATE, PolicyScopeType.ORGANIZATION),
                PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TENANT)));
    }

    private static EffectivePolicy teamMemberPolicy() {
        return new EffectivePolicy(List.of(
                PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TEAM)));
    }
}
