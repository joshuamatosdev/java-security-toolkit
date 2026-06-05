package io.github.joshuamatosdev.security.tenant.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.datasource.factory.DataSourceConfig;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class TenantIsolationAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TenantIsolationAutoConfiguration.class));
    private final ApplicationContextRunner bootDataSourceContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    DataSourceAutoConfiguration.class,
                    TenantIsolationAutoConfiguration.class))
            .withPropertyValues(
                    "spring.datasource.url=jdbc:postgresql://db.example/shared",
                    "spring.datasource.username=tenant_user",
                    "spring.datasource.password=tenant_password",
                    "tenant.binding.claim-secret=0123456789abcdef0123456789abcdef",
                    "tenant.binding.system-ops-password=system_ops_password");

    @Test
    void backsOffBootDataSourceAutoConfigurationWithTenantGuardedDataSource() {
        bootDataSourceContextRunner.run(context -> {
            assertThat(context).hasBean("dataSource");
            assertThat(context.getBean("dataSource")).isInstanceOf(TenantSessionDataSourceProxy.class);
            assertThat(context).hasSingleBean(TenantSessionDataSourceProxy.class);
        });
    }

    @Test
    void backsOffWhenTheApplicationProvidesADataSource() {
        contextRunner
                .withBean(DataSource.class, () -> Mockito.mock(DataSource.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(DataSource.class);
                    assertThat(context).doesNotHaveBean(DataSourceConfig.class);
                });
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("glyptodon.tenant-isolation.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(DataSourceConfig.class));
    }
}
