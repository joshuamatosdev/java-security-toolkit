package io.github.joshuamatosdev.security.tenant.config;

/**
 * Supported tenant placement strategies.
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
