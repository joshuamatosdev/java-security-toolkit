package io.github.joshuamatosdev.security.tenant.datasource.factory;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.config.TenantBindingProperties;
import io.github.joshuamatosdev.security.tenant.config.TenantIsolationProperties;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.time.Clock;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;

/**
 * Spring bean wiring for the tenant-aware datasource boundary.
 *
 * <p>The concrete datasource strategy is selected by {@code tenant.isolation.mode}. ID isolation
 * wraps the shared runtime pool with {@link TenantSessionDataSourceProxy}; schema isolation selects
 * a configured schema on borrow; database isolation routes to a tenant-specific JDBC pool. Every
 * mode still binds the signed tenant claim, so database defaults, checks, or RLS policies can verify
 * the application-selected tenant as defense in depth.
 *
 * <p>Why this exists: factory-owned composition keeps placement mode, runtime credentials, and
 * signed-claim wiring in one auditable construction path.
 */
@SystemTenantBoundary
@Configuration
@EnableConfigurationProperties({TenantIsolationProperties.class, TenantBindingProperties.class})
public class DataSourceConfig {

    private static final String DESTROY_METHOD_CLOSE = "close";

    private final TenantPoolFactory poolFactory;
    private final TenantDataSourceFactory dataSourceFactory;

    /**
     * Creates the datasource configuration component.
     *
     * @param isolationProperties typed tenant placement topology
     * @param bindingProperties session-claim settings used by every isolation mode
     */
    public DataSourceConfig(
            final TenantIsolationProperties isolationProperties,
            final TenantBindingProperties bindingProperties) {
        this(isolationProperties, bindingProperties, Clock.systemUTC());
    }

    /**
     * Creates the datasource configuration component.
     *
     * @param isolationProperties typed tenant placement topology
     * @param bindingProperties session-claim settings used by every isolation mode
     * @param clock clock used to compute signed tenant claim expiry
     */
    @Autowired
    public DataSourceConfig(
            final TenantIsolationProperties isolationProperties,
            final TenantBindingProperties bindingProperties,
            final Clock clock) {
        this.poolFactory = new TenantPoolFactory(isolationProperties, bindingProperties);
        this.dataSourceFactory = new TenantDataSourceFactory(
                isolationProperties,
                poolFactory,
                new TenantClaimSignerFactory(bindingProperties, clock));
    }

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    static Clock tenantIsolationClock() {
        return Clock.systemUTC();
    }

    /**
     * Builds the ordinary tenant runtime pool.
     *
     * <p>The bean is not an autowire candidate by design: callers must receive the primary
     * {@link TenantSessionDataSourceProxy}, not the raw pool, or they could run SQL without a bound
     * tenant claim.
     *
     * @param properties Spring Boot datasource properties for URL, username, password, and driver
     * @return the raw Hikari pool used for ordinary tenant work
     */
    @Lazy
    @Bean(destroyMethod = DESTROY_METHOD_CLOSE, autowireCandidate = false)
    public HikariDataSource tenantRuntimePool(final DataSourceProperties properties) {
        return poolFactory.runtimePool(properties);
    }

    /**
     * Builds the read-only system-operations pool.
     *
     * <p>This pool deliberately keeps URL/driver settings aligned with the runtime pool while
     * overriding both username and password to enforce the separate database role boundary.
     *
     * @param properties Spring Boot datasource properties used as the base pool configuration
     * @return the raw Hikari pool used for system-operations reads
     */
    @Lazy
    @Bean(destroyMethod = DESTROY_METHOD_CLOSE, autowireCandidate = false)
    public HikariDataSource tenantSystemOpsPool(final DataSourceProperties properties) {
        return poolFactory.systemOpsPool(properties);
    }

    /**
     * Exposes read-only pool state for health and metrics integrations without exposing raw pools.
     *
     * <p>Spring Boot health or metrics customizations should consume this bean, or unwrap the
     * primary datasource to {@link TenantPoolInspection}, instead of unwrapping to
     * {@link HikariDataSource}. The raw pools remain non-autowire candidates, so application code
     * cannot borrow unguarded connections.
     *
     * @param properties Spring Boot datasource properties used to locate the managed raw pools
     * @return read-only tenant pool inspection capability
     */
    @Bean
    public TenantPoolInspection tenantPoolInspection(final DataSourceProperties properties) {
        return dataSourceFactory.poolInspection(
                () -> tenantRuntimePool(properties),
                () -> tenantSystemOpsPool(properties));
    }

    /**
     * Exposes the primary tenant-aware datasource.
     *
     * <p>The primary bean is a proxy around a routing datasource, not either raw pool. This preserves
     * a single injection surface while still letting the current tenant context select the physical
     * placement before the signed tenant claim is bound.
     *
     * @param properties Spring Boot datasource properties used to construct the raw pools
     * @param tenantPoolInspection read-only pool state for trusted infrastructure integrations
     * @return the datasource applications and repositories should inject
     */
    @Bean
    @Primary
    public DataSource dataSource(
            final DataSourceProperties properties,
            final TenantPoolInspection tenantPoolInspection) {
        return dataSourceFactory.dataSource(
                () -> tenantRuntimePool(properties),
                () -> tenantSystemOpsPool(properties),
                tenantPoolInspection);
    }
}
