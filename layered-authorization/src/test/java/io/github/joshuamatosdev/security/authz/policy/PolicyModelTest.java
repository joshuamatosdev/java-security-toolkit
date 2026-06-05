package io.github.joshuamatosdev.security.authz.policy;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.authz.policy.rule.PolicyRule;
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
