package io.github.joshuamatosdev.security.authz.decision;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision helper test coverage.
 *
 * <p>Why this is important to test: authorization callers should use the boolean helpers only when
 * they need outcome branching, and pattern-match the records when they need the grant or denial
 * rationale.
 */
class DecisionTest {

    @Test
    void deniedSupportsCallersThatNeedOnlyABinaryDenySignal() {
        assertThat(shouldIncrementDenyMetric(new Deny(DenialReason.NO_MATCHING_RULE))).isTrue();
        assertThat(shouldIncrementDenyMetric(new Allow(GrantBasis.RESOURCE_OWNER))).isFalse();
    }

    private static boolean shouldIncrementDenyMetric(final Decision decision) {
        return decision.denied();
    }
}
