package io.github.joshuamatosdev.security.tenant.config;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.PostgresJdbcUrls;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
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

    private static final Pattern POSTGRES_IDENTIFIER =
            Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final Pattern STABLE_POOL_NAME =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}");
    private static final Pattern JDBC_URL =
            Pattern.compile("jdbc:[A-Za-z][A-Za-z0-9._-]*:\\S+");
    private static final Pattern JAVA_CLASS_NAME =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final Set<String> FORBIDDEN_TENANT_POOL_USERNAMES =
            Set.of("postgres", "ttx", "tenant_bypass", "tenant_ops_user", "application_owner");
    private static final String DUPLICATE_TENANT_ID_PREFIX = "duplicate tenant id ";
    private static final String TENANT_DATABASE_POOL_PREFIX = "tenant-db-";
    private static final String TENANT_MESSAGE_PREFIX = "tenant '";
    private static final String POSTGRES_JDBC_URL_PREFIX = "jdbc:postgresql:";

    private static <T> Map<String, T> immutableCopy(final Map<String, T> tenants) {
        return tenants == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(tenants));
    }

    private static void requireTenantMap(final Map<?, ?> tenants, final String property) {
        if (tenants == null || tenants.isEmpty()) {
            throw new IllegalArgumentException(property + " must contain at least one tenant");
        }
    }

    private static TenantId parseTenantId(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "id");
        try {
            return TenantId.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid UUID id: " + value), ex);
        }
    }

    private static <T> T requireTenantConfig(final String alias, final T tenant) {
        if (tenant == null) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires placement config"));
        }
        return tenant;
    }

    private static String requireSchemaName(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "schema");
        if (!POSTGRES_IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid schema name: " + value));
        }
        return value;
    }

    private static String requireNonBlank(final String alias, final String raw, final String property) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires " + property));
        }
        return raw;
    }

    private static String requireNonBlankWithoutEdgeWhitespace(
            final String alias, final String raw, final String property) {
        final String value = requireNonBlank(alias, raw, property);
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, property + " must not include leading or trailing whitespace"));
        }
        if (containsControlCharacter(value)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, property + " must not contain control characters"));
        }
        return value;
    }

    private static String requireTenantPoolUsername(final String alias, final String raw) {
        final String value = requireNonBlankWithoutEdgeWhitespace(alias, raw, "username");
        if (FORBIDDEN_TENANT_POOL_USERNAMES.contains(value.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "username must not be a privileged or system-ops identity"));
        }
        return value;
    }

    private static String requireJdbcUrl(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "jdbc-url");
        if (containsControlCharacter(value)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "jdbc-url must not contain control characters"));
        }
        if (!JDBC_URL.matcher(value).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid jdbc-url: " + value));
        }
        if (!value.startsWith(POSTGRES_JDBC_URL_PREFIX)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "must be a PostgreSQL jdbc-url: " + value));
        }
        if (PostgresJdbcUrls.containsCredentialQueryParameter(value)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "jdbc-url must not include credential parameters"));
        }
        return value;
    }

    private static void requireOptionalNonBlank(final String alias, final String raw, final String property) {
        if (raw != null && raw.isBlank()) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires non-blank " + property));
        }
    }

    private static void requireOptionalDriverClassName(final String alias, final String raw) {
        requireOptionalNonBlank(alias, raw, "driver-class-name");
        if (raw != null && !JAVA_CLASS_NAME.matcher(raw).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid driver-class-name: " + raw));
        }
    }

    private static void requirePoolName(final String alias, final String raw) {
        if (raw == null) {
            return;
        }
        requireOptionalNonBlank(alias, raw, "pool-name");
        if (!STABLE_POOL_NAME.matcher(raw).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid pool-name: " + raw));
        }
    }

    private static String databasePoolName(final DatabaseTenantProperties placement) {
        if (placement.poolName() != null && !placement.poolName().isBlank()) {
            return placement.poolName();
        }
        return TENANT_DATABASE_POOL_PREFIX + placement.id();
    }

    private static void requirePositive(final String alias, final Integer raw, final String property) {
        if (raw != null && raw <= 0) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires positive " + property));
        }
    }

    private static void requireNonNegative(final String alias, final Integer raw, final String property) {
        if (raw != null && raw < 0) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires non-negative " + property));
        }
    }

    private static void requireMinimumIdleNotAboveMaximum(
            final String alias, final Integer minimumIdle, final Integer maximumPoolSize) {
        if (minimumIdle != null && maximumPoolSize != null && minimumIdle > maximumPoolSize) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "requires minimum-idle to be less than or equal to maximum-pool-size"));
        }
    }

    private static String tenantMessage(final String alias, final String message) {
        return TENANT_MESSAGE_PREFIX + alias + "' " + message;
    }

    private static boolean containsControlCharacter(final String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }
}
