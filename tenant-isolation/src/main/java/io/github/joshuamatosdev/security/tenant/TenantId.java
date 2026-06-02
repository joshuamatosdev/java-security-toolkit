package io.github.joshuamatosdev.security.tenant;

import java.util.UUID;

/**
 * Typed tenant identifier. A {@code UUID} wrapper used at every layer that crosses a tenant
 * boundary — method parameters, repository predicates, cache keys, event envelopes — so that a
 * raw {@code String}/{@code UUID} can never be mistaken for a tenant-scoped value.
 */
public record TenantId(UUID value) {

    public TenantId {
        if (value == null) {
            throw new IllegalArgumentException("TenantId must not be null");
        }
    }

    public TenantId(final String stringValue) {
        this(UUID.fromString(stringValue));
    }

    public static TenantId fromString(final String raw) {
        return new TenantId(UUID.fromString(raw));
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
