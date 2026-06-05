package io.github.joshuamatosdev.security.authz.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.authz.service.AuthorizationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class LayeredAuthorizationAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(LayeredAuthorizationAutoConfiguration.class));

    @Test
    void autoConfiguresAuthorizationService() {
        contextRunner.run(context -> assertThat(context).hasSingleBean(AuthorizationService.class));
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("glyptodon.layered-authorization.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(AuthorizationService.class));
    }
}
