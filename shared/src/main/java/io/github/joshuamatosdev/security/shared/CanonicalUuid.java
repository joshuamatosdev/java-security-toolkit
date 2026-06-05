package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Canonical Uuid for the shared module.
 *
 * <p>Why this exists: central UUID validation keeps every typed identifier strict about canonical
 * text form and null rejection.
 */
final class CanonicalUuid {

    private static final Pattern CANONICAL_UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private CanonicalUuid() {}

    static UUID parse(final String raw, final String typeName) {
        Objects.requireNonNull(raw, typeName + " must not be null");
        if (!CANONICAL_UUID.matcher(raw).matches()) {
            throw new IllegalArgumentException(typeName + " must be a canonical UUID");
        }
        return UUID.fromString(raw);
    }
}
