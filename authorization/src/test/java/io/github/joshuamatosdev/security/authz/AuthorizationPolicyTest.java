package io.github.joshuamatosdev.security.authz;

import io.github.joshuamatosdev.security.authz.decision.*;
import io.github.joshuamatosdev.security.authz.policy.Action;
import io.github.joshuamatosdev.security.authz.policy.PolicyScopeType;
import io.github.joshuamatosdev.security.authz.policy.RoleAssignment;
import io.github.joshuamatosdev.security.authz.policy.Roles;
import io.github.joshuamatosdev.security.authz.policy.rule.EffectivePolicy;
import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;
import io.github.joshuamatosdev.security.authz.principal.PolicyPrincipal;
import io.github.joshuamatosdev.security.authz.principal.PrincipalType;
import io.github.joshuamatosdev.security.authz.principal.ServicePrincipal;
import io.github.joshuamatosdev.security.authz.principal.UserPrincipal;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.authz.request.RequestContext;
import io.github.joshuamatosdev.security.authz.service.AuthorizationPolicy;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TeamId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises every branch of the {@link AuthorizationPolicy} decision in isolation — no Spring, no
 * I/O. Each test pins one access variant (or the deny-by-default tail) so a regression points at the
 * exact branch that changed.
 *
 * <p>Why this is important to test: authorization is a privilege boundary, so the documented
 * route, policy, and audit contracts need executable proof.
 */
class AuthorizationPolicyTest {

    private static final TenantId ACME = new TenantId(UUID.fromString("11111111-1111-1111-1111-111111111111"));
    private static final TenantId GLOBEX = new TenantId(UUID.fromString("99999999-9999-9999-9999-999999999999"));
    private static final OrganizationId ENGINEERING =
        new OrganizationId(UUID.fromString("22222222-2222-2222-2222-222222222222"));
    private static final OrganizationId SALES =
        new OrganizationId(UUID.fromString("23232323-2323-2323-2323-232323232323"));
    private static final ResourceId DOC = new ResourceId(UUID.fromString("33333333-3333-3333-3333-333333333333"));
    private static final String EMAIL_DOMAIN = "@example.test";
    private static final String ADMIN_SUBJECT = "ops";
    private static final String OWNER_SUBJECT = "alice";
    private static final String MEMBER_SUBJECT = "bob";
    private static final String OTHER_OWNER = "someone-else";

    private static final TeamId PLATFORM_TEAM =
        new TeamId(UUID.fromString("44444444-4444-4444-4444-444444444444"));
    private static final TeamId WEB_TEAM =
        new TeamId(UUID.fromString("45454545-4545-4545-4545-454545454545"));

    // The same sane policy the InMemory repository seeds: members read/update within their org, and
    // read tenant-wide; nobody but owner/admin may delete.
    private static final EffectivePolicy SANE_POLICY = new EffectivePolicy(List.of(
        PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION),
        PolicyRule.allow(Roles.MEMBER, Action.UPDATE, PolicyScopeType.ORGANIZATION),
        PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TENANT)));

    // A team-only policy: the sole read grant is TEAM-scoped, so nothing wider can satisfy it.
    private static final EffectivePolicy TEAM_POLICY = new EffectivePolicy(List.of(
        PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TEAM)));

    private final AuthorizationPolicy policy = new AuthorizationPolicy();

    private static UserPrincipal user(final String subject) {
        return new UserPrincipal(subject, subject + EMAIL_DOMAIN, 1L);
    }

    private static RequestContext context(
        final TenantId tenant,
        final OrganizationId organization,
        final Set<RoleAssignment> assignments,
        final PolicyPrincipal principal) {
        return new RequestContext(principal, tenant, organization, assignments, UUID.randomUUID());
    }

    @Test
    void crossTenantRequestIsDeniedBeforeAnyOtherVariant() {
        // Actor is even a wide-scope admin, but in a DIFFERENT tenant than the resource.
        final RequestContext admin =
            context(ACME, null, Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)), user(ADMIN_SUBJECT));
        final ProtectedResource resourceInOtherTenant =
            ProtectedResource.userOwned(DOC, GLOBEX, ENGINEERING, ADMIN_SUBJECT);

        final Decision decision = policy.decide(admin, resourceInOtherTenant, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.TENANT_MISMATCH));
    }

    @Test
    void tenantScopedAdminIsAllowedAsWideScopeEvenForAnActionNoRulePermits() {
        final RequestContext admin =
            context(ACME, null, Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)), user(ADMIN_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        // DELETE has no ALLOW rule for anyone, yet the wide-scope admin is granted.
        final Decision decision = policy.decide(admin, doc, Action.DELETE, SANE_POLICY);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.WIDE_SCOPE_ADMIN));
    }

    @Test
    void explicitDenyRuleOverridesAWideScopeAdminGrant() {
        final EffectivePolicy denyAdminDelete =
            new EffectivePolicy(List.of(PolicyRule.deny(Roles.PLATFORM_ADMIN, Action.DELETE, PolicyScopeType.TENANT)));
        final RequestContext admin =
            context(ACME, null, Set.of(RoleAssignment.tenant(Roles.PLATFORM_ADMIN)), user(ADMIN_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(admin, doc, Action.DELETE, denyAdminDelete);

        assertThat(decision).isEqualTo(new Deny(DenialReason.EXPLICIT_DENY));
    }

    @Test
    void resourceOwnerIsAllowed() {
        final RequestContext owner = context(ACME, ENGINEERING, Set.of(), user(OWNER_SUBJECT));
        final ProtectedResource ownedByAlice =
            ProtectedResource.owned(DOC, ACME, ENGINEERING, PrincipalType.USER, OWNER_SUBJECT);

        final Decision decision = policy.decide(owner, ownedByAlice, Action.DELETE, SANE_POLICY);

        // Owner is granted even DELETE, which no role rule allows.
        assertThat(decision).isEqualTo(new Allow(GrantBasis.RESOURCE_OWNER));
    }

    @Test
    void ownerGrantDoesNotCrossPrincipalTypeNamespaces() {
        final RequestContext serviceWithCollidingKey =
            context(ACME, ENGINEERING, Set.of(), new ServicePrincipal(OWNER_SUBJECT, 1L));
        final ProtectedResource userOwnedResource =
            ProtectedResource.owned(DOC, ACME, ENGINEERING, PrincipalType.USER, OWNER_SUBJECT);

        final Decision decision = policy.decide(serviceWithCollidingKey, userOwnedResource, Action.DELETE, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void organizationMemberIsAllowedForAnOrgScopedAction() {
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, doc, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
    }

    @Test
    void organizationMemberIsDeniedForAnActionNoRulePermits() {
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        // The policy allows a member to READ/UPDATE in-org but not DELETE — per-action granularity.
        final Decision decision = policy.decide(orgMember, doc, Action.DELETE, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void teamScopedGrantAllowsWithinItsTeam() {
        final RequestContext teamMember = context(
            ACME, ENGINEERING,
            Set.of(RoleAssignment.team(Roles.MEMBER, ENGINEERING, PLATFORM_TEAM)),
            user(MEMBER_SUBJECT));
        final ProtectedResource teamDoc =
            new ProtectedResource(DOC, ACME, ENGINEERING, PLATFORM_TEAM, PrincipalType.USER, OTHER_OWNER);

        final Decision decision = policy.decide(teamMember, teamDoc, Action.READ, TEAM_POLICY);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.TEAM_MEMBER));
    }

    @Test
    void teamScopedGrantDoesNotReachAnotherTeam() {
        final RequestContext platformTeamMember = context(
            ACME, ENGINEERING,
            Set.of(RoleAssignment.team(Roles.MEMBER, ENGINEERING, PLATFORM_TEAM)),
            user(MEMBER_SUBJECT));
        final ProtectedResource webTeamDoc =
            new ProtectedResource(DOC, ACME, ENGINEERING, WEB_TEAM, PrincipalType.USER, OTHER_OWNER);

        final Decision decision = policy.decide(platformTeamMember, webTeamDoc, Action.READ, TEAM_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void teamScopedGrantDoesNotReachTeamlessResources() {
        // The org-wide resource is broader than the team grant — narrower scope never widens.
        final RequestContext teamMember = context(
            ACME, ENGINEERING,
            Set.of(RoleAssignment.team(Roles.MEMBER, ENGINEERING, PLATFORM_TEAM)),
            user(MEMBER_SUBJECT));
        final ProtectedResource orgWideDoc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(teamMember, orgWideDoc, Action.READ, TEAM_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void teamScopedGrantDoesNotReachTheSameTeamIdInAnotherOrganization() {
        // Defense against team-identifier reuse: the assignment carries its organization, and both
        // must match the resource.
        final RequestContext salesTeamMember = context(
            ACME, SALES,
            Set.of(RoleAssignment.team(Roles.MEMBER, SALES, PLATFORM_TEAM)),
            user(MEMBER_SUBJECT));
        final ProtectedResource engineeringTeamDoc =
            new ProtectedResource(DOC, ACME, ENGINEERING, PLATFORM_TEAM, PrincipalType.USER, OTHER_OWNER);

        final Decision decision = policy.decide(salesTeamMember, engineeringTeamDoc, Action.READ, TEAM_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void organizationScopedGrantStillReachesTeamPlacedResources() {
        // Teams narrow grants; they do not wall the organization off from its own org-scoped roles.
        final RequestContext orgMember = context(
            ACME, ENGINEERING,
            Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)),
            user(MEMBER_SUBJECT));
        final ProtectedResource teamDoc =
            new ProtectedResource(DOC, ACME, ENGINEERING, PLATFORM_TEAM, PrincipalType.USER, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, teamDoc, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
    }

    @Test
    void teamAllowReportsTheMostSpecificGrantBasis() {
        // The actor qualifies through BOTH a team rule and an org rule; the basis names the narrower.
        final EffectivePolicy teamAndOrg = new EffectivePolicy(List.of(
            PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.TEAM),
            PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION)));
        final RequestContext dualMember = context(
            ACME, ENGINEERING,
            Set.of(
                RoleAssignment.team(Roles.MEMBER, ENGINEERING, PLATFORM_TEAM),
                RoleAssignment.organization(Roles.MEMBER, ENGINEERING)),
            user(MEMBER_SUBJECT));
        final ProtectedResource teamDoc =
            new ProtectedResource(DOC, ACME, ENGINEERING, PLATFORM_TEAM, PrincipalType.USER, OTHER_OWNER);

        final Decision decision = policy.decide(dualMember, teamDoc, Action.READ, teamAndOrg);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.TEAM_MEMBER));
    }

    @Test
    void createIsDeniedByDefaultEvenWhereUpdateIsAllowed() {
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        // Placement with a non-caller owner, so the owner grant stays out of the branch under test.
        final ProtectedResource prospectiveDoc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        // SANE_POLICY allows in-org READ and UPDATE; the new CREATE verb must inherit neither.
        final Decision decision = policy.decide(orgMember, prospectiveDoc, Action.CREATE, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void organizationMemberIsAllowedToCreateOnlyByAnExplicitCreateRule() {
        final EffectivePolicy allowCreate = new EffectivePolicy(List.of(
            PolicyRule.allow(Roles.MEMBER, Action.CREATE, PolicyScopeType.ORGANIZATION)));
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource prospectiveDoc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, prospectiveDoc, Action.CREATE, allowCreate);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
    }

    @Test
    void organizationMemberOfADifferentOrgIsDenied() {
        // Member of SALES, but the resource belongs to ENGINEERING — the org-scoped grant does not reach it.
        final RequestContext salesMember =
            context(ACME, SALES, Set.of(RoleAssignment.organization(Roles.MEMBER, SALES)), user("carol"));
        final ProtectedResource engineeringDoc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(salesMember, engineeringDoc, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }

    @Test
    void tenantWideMemberIsAllowedByEffectivePermission() {
        final RequestContext tenantMember =
            context(ACME, null, Set.of(RoleAssignment.tenant(Roles.MEMBER)), user("dan"));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(tenantMember, doc, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.EFFECTIVE_PERMISSION));
    }

    @Test
    void explicitDenyRuleOverridesAnAllowRule() {
        final EffectivePolicy allowThenDeny = new EffectivePolicy(List.of(
            PolicyRule.allow(Roles.MEMBER, Action.UPDATE, PolicyScopeType.ORGANIZATION),
            PolicyRule.deny(Roles.MEMBER, Action.UPDATE, PolicyScopeType.ORGANIZATION)));
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, doc, Action.UPDATE, allowThenDeny);

        assertThat(decision).isEqualTo(new Deny(DenialReason.EXPLICIT_DENY));
    }

    @Test
    void tenantScopedDenyIsScopeSpecificAndDoesNotReachAnOrganizationScopedHolder() {
        // A TENANT-scoped DENY matches tenant-wide holders, not organization-scoped ones — the same
        // scope-specificity that makes an organization grant not tenant-wide. The org member keeps READ.
        final EffectivePolicy orgAllowTenantDeny = new EffectivePolicy(List.of(
            PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION),
            PolicyRule.deny(Roles.MEMBER, Action.READ, PolicyScopeType.TENANT)));
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, doc, Action.READ, orgAllowTenantDeny);

        assertThat(decision).isEqualTo(new Allow(GrantBasis.ORGANIZATION_MEMBER));
    }

    @Test
    void revokingARoleAcrossScopesRequiresADenyAtEachScope() {
        // Adding the ORGANIZATION-scoped DENY alongside the TENANT-scoped one revokes the org-scoped
        // holder — the supported way to revoke a role fully across scopes.
        final EffectivePolicy denyBothScopes = new EffectivePolicy(List.of(
            PolicyRule.allow(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION),
            PolicyRule.deny(Roles.MEMBER, Action.READ, PolicyScopeType.TENANT),
            PolicyRule.deny(Roles.MEMBER, Action.READ, PolicyScopeType.ORGANIZATION)));
        final RequestContext orgMember =
            context(ACME, ENGINEERING, Set.of(RoleAssignment.organization(Roles.MEMBER, ENGINEERING)), user(MEMBER_SUBJECT));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(orgMember, doc, Action.READ, denyBothScopes);

        assertThat(decision).isEqualTo(new Deny(DenialReason.EXPLICIT_DENY));
    }

    @Test
    void actorWithNoMatchingAssignmentIsDeniedByDefault() {
        // In-tenant, not the owner, holds no role the policy grants — the function ends in deny.
        final RequestContext stranger = context(ACME, null, Set.of(), user("eve"));
        final ProtectedResource doc = ProtectedResource.userOwned(DOC, ACME, ENGINEERING, OTHER_OWNER);

        final Decision decision = policy.decide(stranger, doc, Action.READ, SANE_POLICY);

        assertThat(decision).isEqualTo(new Deny(DenialReason.NO_MATCHING_RULE));
    }
}
