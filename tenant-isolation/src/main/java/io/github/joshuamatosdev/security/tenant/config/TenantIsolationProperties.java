package io.github.joshuamatosdev.security.tenant.config;

import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.DUPLICATE_TENANT_ID_PREFIX;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.databasePoolName;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.immutableCopy;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.parseTenantId;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireJdbcUrl;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireMinimumIdleNotAboveMaximum;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireNonBlankWithoutEdgeWhitespace;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireNonNegative;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireOptionalDriverClassName;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requirePoolName;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requirePositive;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireSchemaName;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireTenantConfig;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireTenantMap;
import static io.github.joshuamatosdev.security.tenant.config.TenantPlacementValidator.requireTenantPoolUsername;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed tenant-isolation topology loaded from YAML or environment-backed Spring configuration.
 *
 * <p>The mode chooses the datasource strategy. The mode-specific tenant maps are deployment
 * topology: callers still supply a trusted {@link io.github.joshuamatosdev.security.tenant.binding.TenantContext},
 * and the datasource resolves that tenant against these allowlisted placements.
 *
 * @param mode active tenant placement strategy; defaults to {@link TenantIsolationMode#ID}
 * @param schema schema-per-tenant placement config
 * @param database database-per-tenant placement config
 *
 * <p>Why this exists: tenant placement is a security boundary, so validation rejects ambiguous or
 * unsafe configuration before any datasource can route traffic.
 */
@ConfigurationProperties("tenant.isolation")
@SystemTenantBoundary
public record TenantIsolationProperties(
        TenantIsolationMode mode,
        SchemaIsolationProperties schema,
        DatabaseIsolationProperties database) {

    /**
     * Applies defaults and validates the active strategy's required placement data.
     */
    public TenantIsolationProperties {
        mode = mode == null ? TenantIsolationMode.ID : mode;
        schema = schema == null ? SchemaIsolationProperties.EMPTY : schema;
        database = database == null ? DatabaseIsolationProperties.EMPTY : database;

        if (mode == TenantIsolationMode.SCHEMA) {
            schema.requireCompleteForSchemaMode();
        }
        if (mode == TenantIsolationMode.DATABASE) {
            database.requireCompleteForDatabaseMode();
        }
    }

    /**
     * Returns schema placements keyed by typed tenant identifier.
     *
     * @return immutable tenant-to-schema map
     */
    public Map<TenantId, String> schemaPlacements() {
        return schema.toPlacements();
    }

    /**
     * Returns database placements keyed by typed tenant identifier.
     *
     * @return immutable tenant-to-database map
     */
    public Map<TenantId, DatabaseTenantProperties> databasePlacements() {
        return database.toPlacements();
    }

    /**
     * Schema-per-tenant placement config.
     *
     * @param tenants tenant alias to schema placement
     */
    public record SchemaIsolationProperties(Map<String, SchemaTenantProperties> tenants) {
        static final SchemaIsolationProperties EMPTY = new SchemaIsolationProperties(Map.of());

        /**
         * Normalizes the tenant map.
         */
        public SchemaIsolationProperties {
            tenants = immutableCopy(tenants);
        }

        private void requireCompleteForSchemaMode() {
            requireTenantMap(tenants, "tenant.isolation.schema.tenants");
            toPlacements();
        }

        private Map<TenantId, String> toPlacements() {
            final Map<TenantId, String> placements = new LinkedHashMap<>();
            final Map<String, TenantId> schemaOwners = new LinkedHashMap<>();
            tenants.forEach((alias, tenant) -> {
                final SchemaTenantProperties requiredTenant = requireTenantConfig(alias, tenant);
                final TenantId tenantId = parseTenantId(alias, requiredTenant.id());
                final String schema = requireSchemaName(alias, requiredTenant.schema());
                final String prior = placements.putIfAbsent(tenantId, schema);
                if (prior != null) {
                    throw new IllegalArgumentException(
                            DUPLICATE_TENANT_ID_PREFIX + tenantId + " in tenant.isolation.schema.tenants");
                }
                final TenantId priorOwner = schemaOwners.putIfAbsent(schema, tenantId);
                if (priorOwner != null) {
                    throw new IllegalArgumentException(
                            "duplicate schema name " + schema + " in tenant.isolation.schema.tenants");
                }
            });
            return Collections.unmodifiableMap(placements);
        }
    }

    /**
     * One tenant's schema placement.
     *
     * @param id canonical tenant UUID
     * @param schema database schema name to select for that tenant
     */
    public record SchemaTenantProperties(String id, String schema) {}

    /**
     * Database-per-tenant placement config.
     *
     * @param tenants tenant alias to database placement
     */
    public record DatabaseIsolationProperties(Map<String, DatabaseTenantProperties> tenants) {
        static final DatabaseIsolationProperties EMPTY = new DatabaseIsolationProperties(Map.of());

        /**
         * Normalizes the tenant map.
         */
        public DatabaseIsolationProperties {
            tenants = immutableCopy(tenants);
        }

        private void requireCompleteForDatabaseMode() {
            requireTenantMap(tenants, "tenant.isolation.database.tenants");
            toPlacements();
        }

        private Map<TenantId, DatabaseTenantProperties> toPlacements() {
            final Map<TenantId, DatabaseTenantProperties> placements = new LinkedHashMap<>();
            final Map<String, TenantId> jdbcUrlOwners = new LinkedHashMap<>();
            final Map<String, TenantId> poolNameOwners = new LinkedHashMap<>();
            tenants.forEach((alias, tenant) -> {
                final DatabaseTenantProperties requiredTenant = requireTenantConfig(alias, tenant);
                final TenantId tenantId = parseTenantId(alias, requiredTenant.id());
                final String jdbcUrl = requireJdbcUrl(alias, requiredTenant.jdbcUrl());
                requireTenantPoolUsername(alias, requiredTenant.username());
                requireNonBlankWithoutEdgeWhitespace(alias, requiredTenant.password(), "password");
                requireOptionalDriverClassName(alias, requiredTenant.driverClassName());
                requirePoolName(alias, requiredTenant.poolName());
                requirePositive(alias, requiredTenant.maximumPoolSize(), "maximum-pool-size");
                requireNonNegative(alias, requiredTenant.minimumIdle(), "minimum-idle");
                requireMinimumIdleNotAboveMaximum(
                        alias, requiredTenant.minimumIdle(), requiredTenant.maximumPoolSize());
                final DatabaseTenantProperties prior = placements.putIfAbsent(tenantId, requiredTenant);
                if (prior != null) {
                    throw new IllegalArgumentException(
                            DUPLICATE_TENANT_ID_PREFIX + tenantId + " in tenant.isolation.database.tenants");
                }
                final TenantId priorJdbcOwner = jdbcUrlOwners.putIfAbsent(jdbcUrl, tenantId);
                if (priorJdbcOwner != null) {
                    throw new IllegalArgumentException(
                            "duplicate jdbc-url " + jdbcUrl + " in tenant.isolation.database.tenants");
                }
                final String poolName = databasePoolName(requiredTenant);
                final TenantId priorPoolOwner = poolNameOwners.putIfAbsent(poolName, tenantId);
                if (priorPoolOwner != null) {
                    throw new IllegalArgumentException(
                            "duplicate pool-name " + poolName + " in tenant.isolation.database.tenants");
                }
            });
            return Collections.unmodifiableMap(placements);
        }
    }

    /**
     * One tenant's database placement.
     *
     * @param id canonical tenant UUID
     * @param jdbcUrl JDBC URL for that tenant's database
     * @param username login role for that tenant's database
     * @param password password for {@code username}; bind from a secret source, not committed YAML
     * @param driverClassName optional JDBC driver class name
     * @param poolName optional Hikari pool name
     * @param maximumPoolSize optional Hikari maximum pool size
     * @param minimumIdle optional Hikari minimum idle count
     */
    public record DatabaseTenantProperties(
            String id,
            String jdbcUrl,
            String username,
            String password,
            String driverClassName,
            String poolName,
            Integer maximumPoolSize,
            Integer minimumIdle) {}
}
