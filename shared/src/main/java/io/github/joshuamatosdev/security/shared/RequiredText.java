package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.Optional;

/**
 * Required single-line text rules shared by configuration and construction boundaries.
 *
 * <p>Modules validate operator-supplied text — key identifiers, pool names, secrets, property
 * values — with the same three rules: not blank, no leading or trailing whitespace, no ISO
 * control characters. This type holds those rules once so every boundary rejects the same
 * malformed values with the same message text.
 *
 * <p>Why this exists: hidden edge whitespace or control characters in operator-supplied text
 * produce look-alike identifiers and confusing logs that are painful to debug; one shared rule
 * set keeps rejection behavior identical at every boundary instead of drifting per module.
 */
public final class RequiredText {

    private RequiredText() {}

    /**
     * Returns the rule-violation message suffix for a value, if any.
     *
     * <p>Callers that need their own exception type or message prefix (a configuration property
     * path, a tenant alias) compose the suffix into their own message, keeping the rule text
     * identical everywhere.
     *
     * @param value text to check
     * @return violation suffix such as {@code "must not be blank"}, or empty when the value passes
     */
    public static Optional<String> violation(final String value) {
        Objects.requireNonNull(value, "value must not be null");
        if (value.isBlank()) {
            return Optional.of("must not be blank");
        }
        if (!value.equals(value.strip())) {
            return Optional.of("must not include leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            return Optional.of("must not contain control characters");
        }
        return Optional.empty();
    }

    /**
     * Requires a non-null, non-blank value without edge whitespace or control characters.
     *
     * @param value text to validate
     * @param name field or property name used in the failure message
     * @return the validated value
     * @throws NullPointerException when the value is null
     * @throws IllegalArgumentException when the value violates a required-text rule
     */
    public static String require(final String value, final String name) {
        Objects.requireNonNull(value, name + " must not be null");
        final Optional<String> violation = violation(value);
        if (violation.isPresent()) {
            throw new IllegalArgumentException(name + " " + violation.get());
        }
        return value;
    }
}
