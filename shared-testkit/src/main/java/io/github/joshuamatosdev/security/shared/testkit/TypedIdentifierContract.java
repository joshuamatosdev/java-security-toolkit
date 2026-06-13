package io.github.joshuamatosdev.security.shared.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.function.Function;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for canonical UUID-backed identifier value objects. */
public interface TypedIdentifierContract<T> {

    /** Creates the identifier from canonical UUID text. */
    Function<String, T> parser();

    /** Expected canonical string value after parsing. */
    default String canonicalUuid() {
        return "0190a000-0000-7000-8000-0000000000a1";
    }

    /** Human-readable type name expected in validation messages. */
    String typeName();

    @Test
    default void canonicalUuidTextRoundTrips() {
        assertThat(parser().apply(canonicalUuid()).toString()).isEqualTo(canonicalUuid());
    }

    @Test
    default void nonCanonicalUuidTextIsRejected() {
        assertThatThrownBy(() -> parser().apply(canonicalUuid().toUpperCase()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(typeName() + " must be a canonical UUID");
    }

    @Test
    default void nilUuidIsRejected() {
        assertThatThrownBy(() -> parser().apply("00000000-0000-0000-0000-000000000000"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(typeName() + " must not be the nil UUID");
    }
}
