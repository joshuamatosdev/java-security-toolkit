package io.github.joshuamatosdev.security.tenant;

import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Wires the runtime connection pool and wraps it with {@link TenantSessionDataSourceProxy} so every
 * borrowed connection is tenant-bound. The pool's credentials (a NON-superuser role) come from
 * {@code spring.datasource.*}; Flyway migrates through a separate, more-privileged identity
 * configured under {@code spring.flyway.*}.
 */
@Configuration
public class DataSourceConfig {

    @Bean
    @Primary
    public DataSource dataSource(final DataSourceProperties properties) {
        final HikariDataSource hikari =
                properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
        return new TenantSessionDataSourceProxy(hikari, "tenant");
    }
}
