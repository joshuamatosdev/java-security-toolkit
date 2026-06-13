package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Typed identifier of the resource an action is being authorized against.
 *
 * <p>Why this exists: resource identifiers are policy inputs, and a dedicated type prevents
 * resource ownership facts from being confused with actor or tenant identity.
 */
public record ResourceId(UUID value) {

    public ResourceId {
        Objects.requireNonNull(value, "ResourceId must not be null");
        CanonicalUuid.requireNotNil(value, "ResourceId");
    }

    public static ResourceId fromString(final String raw) {
        return new ResourceId(CanonicalUuid.parse(raw, "ResourceId"));
    }

    @Override
    public @NonNull String toString() {
        return value.toString();
    }
}
