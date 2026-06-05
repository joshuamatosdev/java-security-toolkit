package io.github.joshuamatosdev.security.authz.principal;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Policy Principal test coverage.
 *
 * <p>Why this is important to test: principal typing separates user and service authority before
 * any policy rule is evaluated.
 */
class PolicyPrincipalTest {

    @Test
    void userPrincipalRejectsBlankIdentityFields() {
        assertThatThrownBy(() -> new UserPrincipal("", "member@example.test", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("subject must not be blank");

        assertThatThrownBy(() -> new UserPrincipal("member", " ", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("email must not be blank");
    }

    @Test
    void userPrincipalRejectsIdentityFieldsWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> new UserPrincipal(" member", "member@example.test", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("subject must not include leading or trailing whitespace");

        assertThatThrownBy(() -> new UserPrincipal("member", "member@example.test ", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("email must not include leading or trailing whitespace");
    }

    @Test
    void servicePrincipalRejectsBlankClientId() {
        assertThatThrownBy(() -> new ServicePrincipal(" ", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("clientId must not be blank");
    }

    @Test
    void servicePrincipalRejectsClientIdWithLeadingOrTrailingWhitespace() {
        assertThatThrownBy(() -> new ServicePrincipal(" svc-report", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("clientId must not include leading or trailing whitespace");

        assertThatThrownBy(() -> new ServicePrincipal("svc-report ", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("clientId must not include leading or trailing whitespace");
    }

    @Test
    void principalsRejectIdentityFieldsWithControlCharacters() {
        assertThatThrownBy(() -> new UserPrincipal("member\nforged", "member@example.test", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("subject must not contain control characters");

        assertThatThrownBy(() -> new UserPrincipal("member", "member@example.test\rforged", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("email must not contain control characters");

        assertThatThrownBy(() -> new ServicePrincipal("svc-report\nforged", 1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("clientId must not contain control characters");
    }

    @Test
    void principalsRejectNegativeAuthorizationVersion() {
        assertThatThrownBy(() -> new UserPrincipal("member", "member@example.test", -1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("authorizationVersion must not be negative");

        assertThatThrownBy(() -> new ServicePrincipal("svc-report", -1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("authorizationVersion must not be negative");
    }
}
