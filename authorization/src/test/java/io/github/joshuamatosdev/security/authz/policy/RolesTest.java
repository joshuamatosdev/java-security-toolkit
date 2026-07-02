package io.github.joshuamatosdev.security.authz.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Roles test coverage.
 *
 * <p>Why this is important to test: these values are shared between Spring's coarse route gate and
 * the fine-grained policy engine, so they must stay bare and stable.
 */
class RolesTest {

    @Test
    void roleVocabularyContainsTheStableBareRoleNames() {
        final List<String> roles = List.of(Roles.PLATFORM_ADMIN, Roles.MEMBER);

        assertThat(roles)
                .containsExactly("PLATFORM_ADMIN", "MEMBER")
                .doesNotHaveDuplicates()
                .allSatisfy(role -> {
                    assertThat(role).isNotBlank();
                    assertThat(role).doesNotStartWith("ROLE_");
                    assertThat(role).isEqualTo(role.strip());
                    assertThat(role.chars()).noneMatch(Character::isISOControl);
                });
    }
}
