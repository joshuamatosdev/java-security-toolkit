package io.github.joshuamatosdev.security.tenant.spring;

import io.github.joshuamatosdev.security.tenant.datasource.factory.DataSourceConfig;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.context.annotation.Import;

/** Auto-configuration entrypoint for tenant-isolation adopters. */
@AutoConfiguration(after = DataSourceAutoConfiguration.class)
@ConditionalOnClass(TenantSessionDataSourceProxy.class)
@ConditionalOnProperty(
        prefix = "glyptodon.tenant-isolation",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true)
@Import(DataSourceConfig.class)
public class TenantIsolationAutoConfiguration {
}
