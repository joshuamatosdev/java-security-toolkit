package io.github.joshuamatosdev.security.tenant.datasource.pool;

import io.github.joshuamatosdev.security.shared.RequiredText;

/**
 * Immutable read-only view of a tenant datasource pool.
 *
 * @param name logical pool name
 * @param activeConnections connections currently borrowed from the pool
 * @param idleConnections idle connections currently retained by the pool
 * @param totalConnections connections currently known to the pool
 * @param threadsAwaitingConnection threads currently waiting for a pool connection
 * @param minimumIdle configured minimum idle connection count
 * @param maximumPoolSize configured maximum pool size
 *
 * <p>The three connection counts are read separately from a live concurrent pool, so they are
 * weakly consistent with each other: a connection mid-transition (or held in an internal state
 * such as Hikari's reserved state) can make {@code totalConnections} differ transiently from
 * {@code activeConnections + idleConnections}. The snapshot deliberately does not enforce a
 * cross-field equality — observability must never fault the datasource surface it observes.
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
        name = requireNonBlankWithoutEdgeWhitespace(name, "name");
        requireNonNegative(activeConnections, "activeConnections");
        requireNonNegative(idleConnections, "idleConnections");
        requireNonNegative(totalConnections, "totalConnections");
        requireNonNegative(threadsAwaitingConnection, "threadsAwaitingConnection");
    }

    private static void requireNonNegative(final int value, final String field) {
        if (value < 0) {
            throw new IllegalArgumentException(field + " must not be negative");
        }
    }

    private static String requireNonBlankWithoutEdgeWhitespace(final String value, final String field) {
        return RequiredText.require(value, field);
    }
}
