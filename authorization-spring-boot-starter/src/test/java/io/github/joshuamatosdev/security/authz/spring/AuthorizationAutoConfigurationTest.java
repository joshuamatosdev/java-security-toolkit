package io.github.joshuamatosdev.security.authz.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.authz.audit.AuthorizationAuditSink;
import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AuthorizationAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AuthorizationAutoConfiguration.class));

    @Test
    void autoConfiguresAuthorizationService() {
        contextRunner.run(context -> assertThat(context).hasSingleBean(AuthorizationService.class));
    }

    @Test
    void backsOffWhenApplicationProvidesAnAuditSink() {
        contextRunner
                .withUserConfiguration(CustomAuditSinkConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationAuditSink.class);
                    assertThat(context).hasSingleBean(AuthorizationService.class);
                });
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("bulwark.authorization.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(AuthorizationService.class));
    }

    @Configuration(proxyBeanMethods = false)
    static class CustomAuditSinkConfiguration {
        @Bean
        AuthorizationAuditSink customAuditSink() {
            return record -> { };
        }
    }
}
