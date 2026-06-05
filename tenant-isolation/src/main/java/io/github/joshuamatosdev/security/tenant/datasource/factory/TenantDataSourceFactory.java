package io.github.joshuamatosdev.security.tenant.datasource.factory;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationMode;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationProperties;
import io.github.joshuamatosdev.security.tenant.datasource.pool.HikariTenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.routing.SystemOpsRoutingDataSource;
import io.github.joshuamatosdev.security.tenant.datasource.routing.TenantDatabaseRoutingDataSource;
import io.github.joshuamatosdev.security.tenant.datasource.routing.TenantSchemaDataSource;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import javax.sql.DataSource;

/**
 * Builds the tenant-aware datasource strategy selected by {@link TenantIsolationMode}.
 *
 * <p>Why this exists: factory-owned composition keeps placement mode, runtime credentials, and
 * signed-claim wiring in one auditable construction path.
 */
@SystemTenantBoundary
final class TenantDataSourceFactory {

    private static final String ID_POOL_NAME = "tenant";
    private static final String SCHEMA_POOL_NAME = "tenant-schema";
    private static final String DATABASE_POOL_NAME = "tenant-database";

    private final TenantIsolationProperties isolationProperties;
    private final TenantPoolFactory poolFactory;
    private final TenantClaimSignerFactory claimSignerFactory;
    private Map<TenantId, HikariDataSource> databasePools;

    /**
     * Creates the datasource strategy factory.
     *
     * @param isolationProperties typed tenant placement topology
     * @param poolFactory raw Hikari pool factory
     * @param claimSignerFactory tenant claim signer factory
     */
    TenantDataSourceFactory(
            final TenantIsolationProperties isolationProperties,
            final TenantPoolFactory poolFactory,
            final TenantClaimSignerFactory claimSignerFactory) {
        this.isolationProperties = Objects.requireNonNull(isolationProperties, "isolationProperties");
        this.poolFactory = Objects.requireNonNull(poolFactory, "poolFactory");
        this.claimSignerFactory = Objects.requireNonNull(claimSignerFactory, "claimSignerFactory");
    }

    /**
     * Creates the inspection surface that matches the configured datasource strategy.
     *
     * @param runtimePool ordinary runtime pool supplier
     * @param systemOpsPool read-only system-ops pool supplier
     * @return read-only tenant pool inspection surface
     */
    TenantPoolInspection poolInspection(
            final Supplier<HikariDataSource> runtimePool,
            final Supplier<HikariDataSource> systemOpsPool) {
        return switch (isolationProperties.mode()) {
            case ID -> new HikariTenantPoolInspection(runtimePool.get(), systemOpsPool.get());
            case SCHEMA -> new HikariTenantPoolInspection(runtimePool.get());
            case DATABASE -> new HikariTenantPoolInspection(databasePools().values());
        };
    }

    /**
     * Creates the primary tenant-aware datasource.
     *
     * @param runtimePool ordinary runtime pool supplier
     * @param systemOpsPool read-only system-ops pool supplier
     * @param tenantPoolInspection read-only pool inspection surface
     * @return datasource applications and repositories should inject
     */
    DataSource dataSource(
            final Supplier<HikariDataSource> runtimePool,
            final Supplier<HikariDataSource> systemOpsPool,
            final TenantPoolInspection tenantPoolInspection) {
        return switch (isolationProperties.mode()) {
            case ID -> idIsolationDataSource(runtimePool, systemOpsPool, tenantPoolInspection);
            case SCHEMA -> schemaIsolationDataSource(runtimePool, tenantPoolInspection);
            case DATABASE -> databaseIsolationDataSource(tenantPoolInspection);
        };
    }

    private DataSource idIsolationDataSource(
            final Supplier<HikariDataSource> runtimePool,
            final Supplier<HikariDataSource> systemOpsPool,
            final TenantPoolInspection tenantPoolInspection) {
        return new TenantSessionDataSourceProxy(
                new SystemOpsRoutingDataSource(runtimePool.get(), systemOpsPool.get()),
                ID_POOL_NAME,
                claimSignerFactory.tenantClaimSigner(),
                tenantPoolInspection);
    }

    private DataSource schemaIsolationDataSource(
            final Supplier<HikariDataSource> runtimePool,
            final TenantPoolInspection tenantPoolInspection) {
        return new TenantSessionDataSourceProxy(
                new TenantSchemaDataSource(
                        runtimePool.get(),
                        isolationProperties.schemaPlacements(),
                        tenantPoolInspection),
                SCHEMA_POOL_NAME,
                claimSignerFactory.tenantClaimSigner(),
                tenantPoolInspection);
    }

    private DataSource databaseIsolationDataSource(final TenantPoolInspection tenantPoolInspection) {
        final Map<TenantId, HikariDataSource> pools = databasePools();
        return new TenantSessionDataSourceProxy(
                new TenantDatabaseRoutingDataSource(pools, tenantPoolInspection),
                DATABASE_POOL_NAME,
                claimSignerFactory.tenantClaimSigner(),
                tenantPoolInspection);
    }

    private synchronized Map<TenantId, HikariDataSource> databasePools() {
        if (databasePools == null) {
            databasePools = Map.copyOf(poolFactory.databasePools(isolationProperties.databasePlacements()));
        }
        return databasePools;
    }
}

