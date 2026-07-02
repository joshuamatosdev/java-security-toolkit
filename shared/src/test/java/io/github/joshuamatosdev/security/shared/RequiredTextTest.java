package io.github.joshuamatosdev.security.shared;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RequiredTextTest {

    private static final char NUL = (char) 0x00;
    private static final char BEL = (char) 0x07;

    @Test
    void safeValuesHaveNoViolation() {
        assertThat(RequiredText.violation("local-ed25519-1")).isEmpty();
        assertThat(RequiredText.violation("x")).isEmpty();
        assertThat(RequiredText.violation("interior space is fine")).isEmpty();
    }

    @Test
    void blankValuesViolateBeforeEdgeWhitespace() {
        assertThat(RequiredText.violation("")).contains("must not be blank");
        assertThat(RequiredText.violation(" ")).contains("must not be blank");
        assertThat(RequiredText.violation("\t")).contains("must not be blank");
    }

    @Test
    void edgeWhitespaceViolates() {
        assertThat(RequiredText.violation(" value"))
                .contains("must not include leading or trailing whitespace");
        assertThat(RequiredText.violation("value "))
                .contains("must not include leading or trailing whitespace");
        assertThat(RequiredText.violation("\tvalue"))
                .contains("must not include leading or trailing whitespace");
    }

    @Test
    void controlCharactersViolate() {
        assertThat(RequiredText.violation("val" + NUL + "ue"))
                .contains("must not contain control characters");
        assertThat(RequiredText.violation("bell" + BEL))
                .contains("must not contain control characters");
        assertThat(RequiredText.violation("multi\nline"))
                .contains("must not contain control characters");
    }

    @Test
    void violationRejectsNull() {
        assertThatThrownBy(() -> RequiredText.violation(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("value must not be null");
    }

    @Test
    void requireReturnsTheValidatedValue() {
        assertThat(RequiredText.require("pool-name", "poolName")).isEqualTo("pool-name");
    }

    @Test
    void requireThrowsWithTheNamedField() {
        assertThatThrownBy(() -> RequiredText.require(null, "poolName"))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("poolName must not be null");
        assertThatThrownBy(() -> RequiredText.require(" ", "poolName"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("poolName must not be blank");
        assertThatThrownBy(() -> RequiredText.require(" x", "poolName"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("poolName must not include leading or trailing whitespace");
        assertThatThrownBy(() -> RequiredText.require("x" + BEL, "poolName"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("poolName must not contain control characters");
    }
}
