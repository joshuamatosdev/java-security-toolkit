package io.github.joshuamatosdev.security.authz.policy;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TeamId;
import org.junit.jupiter.api.Test;

/**
 * Policy Model test coverage.
 *
 * <p>Why this is important to test: policy vocabulary and deny-overrides behavior define who may
 * act on a resource, where regressions become privilege escalation.
 */
class PolicyModelTest {

    @Test
    void roleAssignmentsRejectBlankRoleKeys() {
        assertThatThrownBy(() -> RoleAssignment.tenant(" "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not be blank");
    }

    @Test
    void roleAssignmentsRejectRoleKeysWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> RoleAssignment.tenant(" MEMBER"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not include leading or trailing whitespace");

        assertThatThrownBy(() -> RoleAssignment.tenant("MEMBER "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not include leading or trailing whitespace");
    }

    @Test
    void roleAssignmentsRejectRoleKeysWithControlCharacters() {
        assertThatThrownBy(() -> RoleAssignment.tenant("MEMBER\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not contain control characters");
    }

    @Test
    void teamScopedAssignmentsRequireBothOrganizationAndTeam() {
        final OrganizationId engineering =
                OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
        final TeamId platformTeam = TeamId.fromString("0190a000-0000-7000-8000-0000000000f1");

        assertThatThrownBy(() -> new RoleAssignment("MEMBER", PolicyScopeType.TEAM, engineering, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("a TEAM-scoped assignment requires both its organization scopeId and its teamScopeId");
        assertThatThrownBy(() -> new RoleAssignment("MEMBER", PolicyScopeType.TEAM, null, platformTeam))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("a TEAM-scoped assignment requires both its organization scopeId and its teamScopeId");
    }

    @Test
    void onlyTeamScopedAssignmentsMayCarryATeam() {
        final OrganizationId engineering =
                OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
        final TeamId platformTeam = TeamId.fromString("0190a000-0000-7000-8000-0000000000f1");

        assertThatThrownBy(() -> new RoleAssignment("MEMBER", PolicyScopeType.ORGANIZATION, engineering, platformTeam))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("only a TEAM-scoped assignment may carry a teamScopeId");
        assertThatThrownBy(() -> new RoleAssignment("MEMBER", PolicyScopeType.TENANT, null, platformTeam))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("only a TEAM-scoped assignment may carry a teamScopeId");
    }

    @Test
    void policyRulesRejectBlankRoleKeys() {
        assertThatThrownBy(() -> PolicyRule.allow(" ", Action.READ, PolicyScopeType.TENANT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not be blank");
    }

    @Test
    void policyRulesRejectRoleKeysWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> PolicyRule.allow(" MEMBER", Action.READ, PolicyScopeType.TENANT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not include leading or trailing whitespace");

        assertThatThrownBy(() -> PolicyRule.allow("MEMBER ", Action.READ, PolicyScopeType.TENANT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not include leading or trailing whitespace");
    }

    @Test
    void policyRulesRejectRoleKeysWithControlCharacters() {
        assertThatThrownBy(() -> PolicyRule.allow("MEMBER\rforged", Action.READ, PolicyScopeType.TENANT))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("roleKey must not contain control characters");
    }
}
