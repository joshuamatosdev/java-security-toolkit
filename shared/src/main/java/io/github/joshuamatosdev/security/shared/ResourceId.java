package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Typed identifier of the resource an action is being authorized against.
 */
public record ResourceId(UUID value) {

    public ResourceId {
        Objects.requireNonNull(value, "ResourceId must not be null");
    }

    public static ResourceId fromString(final String raw) {
        return new ResourceId(UUID.fromString(raw));
    }

    @Override
    public @NonNull String toString() {
        return value.toString();
    }
}
