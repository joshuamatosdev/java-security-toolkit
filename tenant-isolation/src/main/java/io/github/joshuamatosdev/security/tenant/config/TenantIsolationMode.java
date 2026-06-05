package io.github.joshuamatosdev.security.tenant.config;

/**
 * Supported tenant placement strategies.
 *
 * <p>Why this exists: tenant placement is a security boundary, so validation rejects ambiguous or
 * unsafe configuration before any datasource can route traffic.
 */
public enum TenantIsolationMode {
    /**
     * Shared tables carry a {@code tenant_id}; PostgreSQL Row-Level Security enforces visibility.
     */
    ID,

    /**
     * One PostgreSQL schema per tenant in a shared database.
     */
    SCHEMA,

    /**
     * One database, or JDBC endpoint, per tenant.
     */
    DATABASE
}
