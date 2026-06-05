package io.github.joshuamatosdev.security.tenant.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.datasource.factory.DataSourceConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class TenantIsolationAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TenantIsolationAutoConfiguration.class));

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("glyptodon.tenant-isolation.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(DataSourceConfig.class));
    }
}
