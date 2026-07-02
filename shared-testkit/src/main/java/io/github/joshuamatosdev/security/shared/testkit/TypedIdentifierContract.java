package io.github.joshuamatosdev.security.shared.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Reusable contract tests for canonical UUID-backed identifier value objects: parse round-trip,
 * canonical-form and nil rejection, null and malformed-text rejection, and value equality.
 */
public interface TypedIdentifierContract<T> {

    /** Creates the identifier from canonical UUID text. */
    Function<String, T> parser();

    /** Expected canonical string value after parsing. */
    default String canonicalUuid() {
        return "0190a000-0000-7000-8000-0000000000a1";
    }

    /**
     * A second canonical UUID, guaranteed different from {@link #canonicalUuid()}. Implementations
     * that override one must keep the two distinct.
     */
    default String distinctCanonicalUuid() {
        return "0190a000-0000-7000-8000-0000000000b2";
    }

    /** Human-readable type name expected in validation messages. */
    String typeName();

    @Test
    default void canonicalUuidTextRoundTrips() {
        assertThat(parser().apply(canonicalUuid()).toString()).isEqualTo(canonicalUuid());
    }

    @Test
    default void nonCanonicalUuidTextIsRejected() {
        // A fixed uppercase literal, not a transform of canonicalUuid(): an override with a
        // letter-free UUID would make toUpperCase() the identity and invert the test's meaning.
        assertThatThrownBy(() -> parser().apply("0190A000-0000-7000-8000-0000000000A1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(typeName() + " must be a canonical UUID");
    }

    @Test
    default void malformedTextIsRejected() {
        assertThatThrownBy(() -> parser().apply("not-a-uuid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(typeName() + " must be a canonical UUID");
    }

    @Test
    default void nullTextIsRejected() {
        assertThatThrownBy(() -> parser().apply(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage(typeName() + " must not be null");
    }

    @Test
    default void nilUuidIsRejected() {
        assertThatThrownBy(() -> parser().apply("00000000-0000-0000-0000-000000000000"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(typeName() + " must not be the nil UUID");
    }

    @Test
    default void equalTextParsesToEqualValues() {
        assertThat(parser().apply(canonicalUuid()))
                .isEqualTo(parser().apply(canonicalUuid()))
                .hasSameHashCodeAs(parser().apply(canonicalUuid()));
    }

    @Test
    default void distinctTextParsesToDistinctValues() {
        assertThat(parser().apply(canonicalUuid())).isNotEqualTo(parser().apply(distinctCanonicalUuid()));
    }
}
