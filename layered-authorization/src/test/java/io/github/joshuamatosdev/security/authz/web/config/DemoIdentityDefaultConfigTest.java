package io.github.joshuamatosdev.security.authz.web.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

class DemoIdentityDefaultConfigTest {

    @Test
    void packagedDefaultDoesNotEnableDemoIdentity() {
        final Properties properties = load("application.yaml");

        assertThat(properties.getProperty("showcase.demo-identity")).isEqualTo("false");
    }

    @Test
    void showcaseProfileExplicitlyOptsInToDemoIdentity() {
        final Properties properties = load("application-showcase.yaml");

        assertThat(properties.getProperty("showcase.demo-identity")).isEqualTo("true");
    }

    private static Properties load(final String resource) {
        final YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new ClassPathResource(resource));
        final Properties properties = factory.getObject();
        assertThat(properties).isNotNull();
        return properties;
    }
}
