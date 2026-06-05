package io.github.joshuamatosdev.security.edge.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class EdgePerimeterAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(EdgePerimeterAutoConfiguration.class));

    @Test
    void doesNotAutoConfigureOutsideReactiveWebApplications() {
        contextRunner.run(context -> assertThat(context).doesNotHaveBean(EdgePerimeterProperties.class));
    }

    @Test
    void canBeDisabled() {
        contextRunner
                .withPropertyValues("glyptodon.edge-perimeter.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(EdgePerimeterProperties.class));
    }
}
