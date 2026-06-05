package io.github.joshuamatosdev.security.tenant.datasource.pool;

import java.util.Objects;

/**
 * Immutable read-only view of a tenant datasource pool.
 *
 * @param name logical pool name
 * @param activeConnections connections currently borrowed from the pool
 * @param idleConnections idle connections currently retained by the pool
 * @param totalConnections active plus idle connections currently known to the pool
 * @param threadsAwaitingConnection threads currently waiting for a pool connection
 * @param minimumIdle configured minimum idle connection count
 * @param maximumPoolSize configured maximum pool size
 *
 * <p>Why this exists: pool inspection makes runtime pool identity observable so tests can prove
 * least-privilege tenant connections are really in use.
 */
public record TenantPoolSnapshot(
        String name,
        int activeConnections,
        int idleConnections,
        int totalConnections,
        int threadsAwaitingConnection,
        int minimumIdle,
        int maximumPoolSize) {

    /**
     * Validates record invariants for a captured pool snapshot.
     */
    public TenantPoolSnapshot {
        Objects.requireNonNull(name, "name");
        requireNonNegative(activeConnections, "activeConnections");
        requireNonNegative(idleConnections, "idleConnections");
        requireNonNegative(totalConnections, "totalConnections");
        requireNonNegative(threadsAwaitingConnection, "threadsAwaitingConnection");
        final long expectedTotalConnections = (long) activeConnections + idleConnections;
        if (totalConnections != expectedTotalConnections) {
            throw new IllegalArgumentException(
                    "totalConnections must equal activeConnections plus idleConnections");
        }
    }

    private static void requireNonNegative(final int value, final String field) {
        if (value < 0) {
            throw new IllegalArgumentException(field + " must not be negative");
        }
    }
}

