package io.github.joshuamatosdev.security.tenant.datasource.factory;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.PostgresJdbcUrls;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationMode;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationProperties;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;

/**
 * Creates raw Hikari pools used behind guarded tenant datasources.
 *
 * <p>Why this exists: factory-owned composition keeps placement mode, runtime credentials, and
 * signed-claim wiring in one auditable construction path.
 */
@SystemTenantBoundary
final class TenantPoolFactory {

    static final String RUNTIME_POOL_NAME = "tenant-runtime";
    static final String SYSTEM_OPS_POOL_NAME = "tenant-system-ops";
    static final String TENANT_DATABASE_POOL_PREFIX = "tenant-db-";
    static final String SYSTEM_OPS_USERNAME = "tenant_ops_user";
    private static final Pattern JDBC_URL =
            Pattern.compile("jdbc:[A-Za-z][A-Za-z0-9._-]*:\\S+");
    private static final String POSTGRES_JDBC_URL_PREFIX = "jdbc:postgresql:";
    private static final Set<String> FORBIDDEN_RUNTIME_POOL_USERNAMES =
            Set.of("postgres", "app_superuser", "tenant_bypass", SYSTEM_OPS_USERNAME, "application_owner");

    private final TenantIsolationProperties isolationProperties;
    private final TenantBindingProperties bindingProperties;

    /**
     * Creates the pool factory.
     *
     * @param isolationProperties typed tenant placement topology
     * @param bindingProperties RLS session-claim settings used by ID isolation
     */
    TenantPoolFactory(
            final TenantIsolationProperties isolationProperties,
            final TenantBindingProperties bindingProperties) {
        this.isolationProperties = Objects.requireNonNull(isolationProperties, "isolationProperties");
        this.bindingProperties = Objects.requireNonNull(bindingProperties, "bindingProperties");
    }

    /**
     * Builds the ordinary shared runtime pool.
     *
     * @param properties Spring Boot datasource properties for URL, username, password, and driver
     * @return raw Hikari pool used for ordinary tenant work
     */
    HikariDataSource runtimePool(final DataSourceProperties properties) {
        requirePostgresRuntimeJdbcUrl(properties);
        requireTenantRuntimeUsername(properties);
        requireTenantRuntimePassword(properties);
        final HikariDataSource hikari =
                properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
        hikari.setPoolName(RUNTIME_POOL_NAME);
        return hikari;
    }

    /**
     * Builds the read-only system-operations pool for ID isolation.
     *
     * @param properties Spring Boot datasource properties used as the base pool configuration
     * @return raw Hikari pool used for system-operations reads
     */
    HikariDataSource systemOpsPool(final DataSourceProperties properties) {
        requirePostgresRuntimeJdbcUrl(properties);
        final HikariDataSource hikari =
                properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
        hikari.setUsername(SYSTEM_OPS_USERNAME);
        hikari.setPassword(systemOpsPassword());
        hikari.setPoolName(SYSTEM_OPS_POOL_NAME);
        return hikari;
    }

    /**
     * Builds tenant-specific database pools from allowlisted placement config.
     *
     * @param placements tenant-to-database placement map
     * @return raw Hikari pools keyed by tenant
     */
    Map<TenantId, HikariDataSource> databasePools(
            final Map<TenantId, TenantIsolationProperties.DatabaseTenantProperties> placements) {
        final Map<TenantId, HikariDataSource> pools = new LinkedHashMap<>();
        placements.forEach((tenant, placement) -> pools.put(tenant, tenantDatabasePool(placement)));
        return pools;
    }

    private HikariDataSource tenantDatabasePool(
            final TenantIsolationProperties.DatabaseTenantProperties placement) {
        final HikariDataSource hikari = new HikariDataSource();
        hikari.setJdbcUrl(placement.jdbcUrl());
        hikari.setUsername(placement.username());
        hikari.setPassword(placement.password());
        if (placement.driverClassName() != null && !placement.driverClassName().isBlank()) {
            hikari.setDriverClassName(placement.driverClassName());
        }
        hikari.setPoolName(poolName(placement));
        if (placement.maximumPoolSize() != null) {
            hikari.setMaximumPoolSize(placement.maximumPoolSize());
        }
        if (placement.minimumIdle() != null) {
            hikari.setMinimumIdle(placement.minimumIdle());
        }
        return hikari;
    }

    private static String poolName(final TenantIsolationProperties.DatabaseTenantProperties placement) {
        if (placement.poolName() != null && !placement.poolName().isBlank()) {
            return placement.poolName();
        }
        return TENANT_DATABASE_POOL_PREFIX + placement.id();
    }

    private String systemOpsPassword() {
        if (isolationProperties.mode() == TenantIsolationMode.ID) {
            return bindingProperties.requireSystemOpsPasswordForIdMode();
        }
        return bindingProperties.systemOpsPasswordOrEmpty();
    }

    private static void requirePostgresRuntimeJdbcUrl(final DataSourceProperties properties) {
        Objects.requireNonNull(properties, "properties must not be null");
        final String jdbcUrl = properties.getUrl();
        if (jdbcUrl == null || jdbcUrl.isBlank()) {
            throw new IllegalStateException(
                    "spring.datasource.url must name the PostgreSQL tenant runtime database");
        }
        RequiredText.violation(jdbcUrl).ifPresent(violation -> {
            throw new IllegalStateException("spring.datasource.url " + violation);
        });
        if (!JDBC_URL.matcher(jdbcUrl).matches()) {
            throw new IllegalStateException("spring.datasource.url must be a valid JDBC URL");
        }
        if (!jdbcUrl.startsWith(POSTGRES_JDBC_URL_PREFIX)) {
            throw new IllegalStateException(
                    "spring.datasource.url must be a PostgreSQL jdbc-url");
        }
        final var unsafeParameter = PostgresJdbcUrls.firstUnsafeQueryParameter(jdbcUrl);
        if (unsafeParameter.isPresent()) {
            throw new IllegalStateException(
                    "spring.datasource.url must not include unsafe JDBC URL query parameter: "
                            + unsafeParameter.get());
        }
    }

    private static void requireTenantRuntimeUsername(final DataSourceProperties properties) {
        final String username = properties.getUsername();
        if (username == null || username.isBlank()) {
            throw new IllegalStateException("spring.datasource.username must name the tenant runtime role");
        }
        RequiredText.violation(username).ifPresent(violation -> {
            throw new IllegalStateException("spring.datasource.username " + violation);
        });
        if (FORBIDDEN_RUNTIME_POOL_USERNAMES.contains(username.toLowerCase(Locale.ROOT))) {
            throw new IllegalStateException(
                    "spring.datasource.username must not be a privileged or system-ops identity");
        }
    }

    private static void requireTenantRuntimePassword(final DataSourceProperties properties) {
        final String password = properties.getPassword();
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("spring.datasource.password must name the tenant runtime role password");
        }
        RequiredText.violation(password).ifPresent(violation -> {
            throw new IllegalStateException("spring.datasource.password " + violation);
        });
    }
}
