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
import java.util.Objects;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Immutable, validated tenant-isolation topology loaded from Spring configuration.
 *
 * <p>Raw configuration is converted to typed placements once at the construction boundary. Pool
 * and routing code only receives those validated values; it does not repeat parsing or policy.
 */
@ConfigurationProperties("tenant.isolation")
@SystemTenantBoundary
public final class TenantIsolationProperties {

    private final TenantIsolationMode mode;
    private final SchemaIsolationProperties schema;
    private final DatabaseIsolationProperties database;
    private final Map<TenantId, String> schemaPlacements;
    private final Map<TenantId, DatabasePlacement> databasePlacements;

    /** Applies defaults and validates all supplied topology. */
    public TenantIsolationProperties(
            final TenantIsolationMode mode,
            final SchemaIsolationProperties schema,
            final DatabaseIsolationProperties database) {
        this.mode = mode == null ? TenantIsolationMode.ID : mode;
        this.schema = schema == null ? SchemaIsolationProperties.EMPTY : schema;
        this.database = database == null ? DatabaseIsolationProperties.EMPTY : database;

        if (this.mode == TenantIsolationMode.SCHEMA) {
            requireTenantMap(this.schema.tenants(), "tenant.isolation.schema.tenants");
        }
        if (this.mode == TenantIsolationMode.DATABASE) {
            requireTenantMap(this.database.tenants(), "tenant.isolation.database.tenants");
        }

        this.schemaPlacements = this.schema.tenants().isEmpty()
                ? Map.of()
                : buildSchemaPlacements(this.schema.tenants());
        this.databasePlacements = this.database.tenants().isEmpty()
                ? Map.of()
                : buildDatabasePlacements(this.database.tenants());
    }

    public TenantIsolationMode mode() {
        return mode;
    }

    public SchemaIsolationProperties schema() {
        return schema;
    }

    public DatabaseIsolationProperties database() {
        return database;
    }

    /** Returns the already-validated schema placement table. */
    public Map<TenantId, String> schemaPlacements() {
        return schemaPlacements;
    }

    /** Returns the already-validated database placement table. */
    public Map<TenantId, DatabasePlacement> databasePlacements() {
        return databasePlacements;
    }

    private static Map<TenantId, String> buildSchemaPlacements(
            final Map<String, SchemaTenantProperties> tenants) {
        final Map<TenantId, String> placements = new LinkedHashMap<>();
        final Map<String, TenantId> schemaOwners = new LinkedHashMap<>();
        tenants.forEach((alias, tenant) -> {
            final SchemaTenantProperties requiredTenant = requireTenantConfig(alias, tenant);
            final TenantId tenantId = parseTenantId(alias, requiredTenant.id());
            final String schema = requireSchemaName(alias, requiredTenant.schema());
            if (placements.putIfAbsent(tenantId, schema) != null) {
                throw new IllegalArgumentException(
                        DUPLICATE_TENANT_ID_PREFIX + tenantId + " in tenant.isolation.schema.tenants");
            }
            if (schemaOwners.putIfAbsent(schema, tenantId) != null) {
                throw new IllegalArgumentException(
                        "duplicate schema name " + schema + " in tenant.isolation.schema.tenants");
            }
        });
        return Collections.unmodifiableMap(placements);
    }

    private static Map<TenantId, DatabasePlacement> buildDatabasePlacements(
            final Map<String, DatabaseTenantProperties> tenants) {
        final Map<TenantId, DatabasePlacement> placements = new LinkedHashMap<>();
        final Map<String, TenantId> jdbcUrlOwners = new LinkedHashMap<>();
        final Map<String, TenantId> poolNameOwners = new LinkedHashMap<>();
        tenants.forEach((alias, tenant) -> {
            final DatabaseTenantProperties requiredTenant = requireTenantConfig(alias, tenant);
            final TenantId tenantId = parseTenantId(alias, requiredTenant.id());
            final String jdbcUrl = requireJdbcUrl(alias, requiredTenant.jdbcUrl());
            final String username = requireTenantPoolUsername(alias, requiredTenant.username());
            final String password =
                    requireNonBlankWithoutEdgeWhitespace(alias, requiredTenant.password(), "password");
            requireOptionalDriverClassName(alias, requiredTenant.driverClassName());
            requirePoolName(alias, requiredTenant.poolName());
            requirePositive(alias, requiredTenant.maximumPoolSize(), "maximum-pool-size");
            requireNonNegative(alias, requiredTenant.minimumIdle(), "minimum-idle");
            requireMinimumIdleNotAboveMaximum(
                    alias, requiredTenant.minimumIdle(), requiredTenant.maximumPoolSize());
            final String poolName = databasePoolName(tenantId, requiredTenant);
            final DatabasePlacement placement = new DatabasePlacement(
                    jdbcUrl,
                    username,
                    password,
                    requiredTenant.driverClassName(),
                    poolName,
                    requiredTenant.maximumPoolSize(),
                    requiredTenant.minimumIdle());
            if (placements.putIfAbsent(tenantId, placement) != null) {
                throw new IllegalArgumentException(
                        DUPLICATE_TENANT_ID_PREFIX + tenantId + " in tenant.isolation.database.tenants");
            }
            if (jdbcUrlOwners.putIfAbsent(jdbcUrl, tenantId) != null) {
                throw new IllegalArgumentException(
                        "duplicate jdbc-url " + jdbcUrl + " in tenant.isolation.database.tenants");
            }
            if (poolNameOwners.putIfAbsent(poolName, tenantId) != null) {
                throw new IllegalArgumentException(
                        "duplicate pool-name " + poolName + " in tenant.isolation.database.tenants");
            }
        });
        return Collections.unmodifiableMap(placements);
    }

    /** Schema-per-tenant source configuration. */
    public record SchemaIsolationProperties(Map<String, SchemaTenantProperties> tenants) {
        static final SchemaIsolationProperties EMPTY = new SchemaIsolationProperties(Map.of());

        public SchemaIsolationProperties {
            tenants = immutableCopy(tenants);
        }
    }

    /** One tenant's schema source configuration. */
    public record SchemaTenantProperties(String id, String schema) {}

    /** Database-per-tenant source configuration. */
    public record DatabaseIsolationProperties(Map<String, DatabaseTenantProperties> tenants) {
        static final DatabaseIsolationProperties EMPTY = new DatabaseIsolationProperties(Map.of());

        public DatabaseIsolationProperties {
            tenants = immutableCopy(tenants);
        }
    }

    /** One tenant's database source configuration. */
    public record DatabaseTenantProperties(
            String id,
            String jdbcUrl,
            String username,
            String password,
            String driverClassName,
            String poolName,
            Integer maximumPoolSize,
            Integer minimumIdle) {}

    /** Validated database placement consumed by pool creation. */
    public static final class DatabasePlacement {
        private final String jdbcUrl;
        private final String username;
        private final String password;
        private final String driverClassName;
        private final String poolName;
        private final Integer maximumPoolSize;
        private final Integer minimumIdle;

        private DatabasePlacement(
                final String jdbcUrl,
                final String username,
                final String password,
                final String driverClassName,
                final String poolName,
                final Integer maximumPoolSize,
                final Integer minimumIdle) {
            this.jdbcUrl = Objects.requireNonNull(jdbcUrl, "jdbcUrl");
            this.username = Objects.requireNonNull(username, "username");
            this.password = Objects.requireNonNull(password, "password");
            this.driverClassName = driverClassName;
            this.poolName = Objects.requireNonNull(poolName, "poolName");
            this.maximumPoolSize = maximumPoolSize;
            this.minimumIdle = minimumIdle;
        }

        public String jdbcUrl() {
            return jdbcUrl;
        }

        public String username() {
            return username;
        }

        public String password() {
            return password;
        }

        public String driverClassName() {
            return driverClassName;
        }

        public String poolName() {
            return poolName;
        }

        public Integer maximumPoolSize() {
            return maximumPoolSize;
        }

        public Integer minimumIdle() {
            return minimumIdle;
        }
    }
}
