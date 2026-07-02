package io.github.joshuamatosdev.security.authz.web.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.authz.policy.Roles;
import org.junit.jupiter.api.Test;

/**
 * Access Rule test coverage.
 *
 * <p>Why this is important to test: authorization bugs become route-level privilege bugs, so the
 * web boundary must prove deny-by-default and scoped access behavior.
 */
class AccessRuleTest {

    @Test
    void restrictedRuleRequiresAtLeastOneRole() {
        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("restricted access rules must name at least one role");
    }

    @Test
    void restrictedRuleRejectsBlankRole() {
        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN, " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role must not be blank");
    }

    @Test
    void restrictedRuleRejectsRolesWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN, " " + Roles.PLATFORM_ADMIN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role must not include leading or trailing whitespace");

        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN, Roles.PLATFORM_ADMIN + " "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role must not include leading or trailing whitespace");
    }

    @Test
    void restrictedRuleRejectsRolesWithControlCharacters() {
        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN, Roles.PLATFORM_ADMIN + "\nforged"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role must not contain control characters");
    }

    @Test
    void restrictedRuleRejectsAlreadyPrefixedRole() {
        assertThatThrownBy(() -> AccessRule.any(SecurityUrlGroup.ADMIN, "ROLE_" + Roles.PLATFORM_ADMIN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("role must be bare; do not include ROLE_");
    }

    @Test
    void restrictedRuleKeepsBareRoleValues() {
        final AccessRule rule = AccessRule.any(SecurityUrlGroup.ADMIN, Roles.PLATFORM_ADMIN);

        assertThat(rule.roles()).containsExactly(Roles.PLATFORM_ADMIN);
    }
}
