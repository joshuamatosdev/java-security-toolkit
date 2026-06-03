package io.github.joshuamatosdev.security.tenant.datasource.factory;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationMode;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationProperties;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;

/**
 * Creates raw Hikari pools used behind guarded tenant datasources.
 */
@SystemTenantBoundary
final class TenantPoolFactory {

    static final String RUNTIME_POOL_NAME = "tenant-runtime";
    static final String SYSTEM_OPS_POOL_NAME = "tenant-system-ops";
    static final String TENANT_DATABASE_POOL_PREFIX = "tenant-db-";
    static final String SYSTEM_OPS_USERNAME = "tenant_ops_user";

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
}


