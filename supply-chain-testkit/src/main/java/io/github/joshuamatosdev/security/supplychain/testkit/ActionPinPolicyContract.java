package io.github.joshuamatosdev.security.supplychain.testkit;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.supplychain.policy.ActionPinPolicy;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for workflow-action pin policy implementations. */
public interface ActionPinPolicyContract {

    /** Policy under test. */
    ActionPinPolicy policy();

    @Test
    default void shaPinnedReferencesAreAcceptedAndMutableRefsAreRejected() {
        assertThat(policy().isShaPinned("acme/checkout@" + "a".repeat(40))).isTrue();
        assertThat(policy().isShaPinned("acme/checkout@" + "A".repeat(40))).isFalse();
        assertThat(policy().isShaPinned("acme/checkout@v4")).isFalse();
        assertThat(policy().isShaPinned("acme/checkout@main")).isFalse();
        assertThat(policy().isShaPinned(null)).isFalse();
    }

    @Test
    default void workflowsWithMutableExternalRefsFail() throws IOException {
        final Path workflow = Files.createTempFile("action-pin-policy-contract", ".yml");
        try {
            Files.writeString(
                    workflow,
                    """
                    jobs:
                      build:
                        steps:
                          - uses: acme/checkout@%s
                          - uses: acme/setup-tool@v4
                          - uses: ./.github/actions/local-step
                    """
                            .formatted("a".repeat(40)));

            assertThat(policy().unpinnedActionRefs(workflow)).containsExactly("acme/setup-tool@v4");
        } finally {
            Files.deleteIfExists(workflow);
        }
    }
}
