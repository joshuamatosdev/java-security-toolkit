package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Canonical Uuid for the shared module.
 *
 * <p>Why this exists: central UUID validation keeps every typed identifier strict about canonical
 * text form, null rejection, and rejection of the reserved nil UUID
 * ({@code 00000000-0000-0000-0000-000000000000}) — a sentinel/zeroed value must never flow as a
 * tenant, organization, or resource identity.
 */
final class CanonicalUuid {

    private static final Pattern CANONICAL_UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private static final UUID NIL = new UUID(0L, 0L);

    private CanonicalUuid() {}

    static UUID parse(final String raw, final String typeName) {
        Objects.requireNonNull(raw, typeName + " must not be null");
        if (!CANONICAL_UUID.matcher(raw).matches()) {
            throw new IllegalArgumentException(typeName + " must be a canonical UUID");
        }
        return requireNotNil(UUID.fromString(raw), typeName);
    }

    /**
     * Rejects the reserved nil UUID. Null-safe: a {@code null} value passes through here unchanged so
     * each typed identifier keeps its own null-rejection contract.
     */
    static UUID requireNotNil(final UUID value, final String typeName) {
        if (NIL.equals(value)) {
            throw new IllegalArgumentException(typeName + " must not be the nil UUID");
        }
        return value;
    }
}
