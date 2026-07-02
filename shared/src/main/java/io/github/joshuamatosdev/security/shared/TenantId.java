package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Typed tenant identifier. A {@code UUID} wrapper used at every layer that crosses a tenant
 * boundary — method parameters, repository predicates, cache keys, event envelopes — so that a
 * raw {@code String}/{@code UUID} can never be mistaken for a tenant-scoped value.
 *
 * <p>Why this exists: tenant identifiers are passed across many module boundaries, and a dedicated
 * type prevents raw UUID mixups from becoming cross-tenant bugs.
 */
public record TenantId(UUID value) {

    public TenantId {
        Objects.requireNonNull(value, "TenantId must not be null");
        CanonicalUuid.requireNotNil(value, "TenantId");
    }

    public static TenantId fromString(final String raw) {
        return new TenantId(CanonicalUuid.parse(raw, "TenantId"));
    }

    @Override
    public @NonNull String toString() {
        return value.toString();
    }
}
