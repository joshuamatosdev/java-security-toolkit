package io.github.joshuamatosdev.security.authz.web.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

/**
 * Demo Identity Default Config test coverage.
 *
 * <p>Why this is important to test: authorization bugs become route-level privilege bugs, so the
 * web boundary must prove deny-by-default and scoped access behavior.
 */
class DemoIdentityDefaultConfigTest {

    @Test
    void packagedDefaultDoesNotEnableDemoIdentity() {
        final Properties properties = load("application.yaml");

        assertThat(properties.getProperty("showcase.demo-identity")).isEqualTo("false");
        assertThat(properties).doesNotContainKey("authorization.demo-policy.enabled");
    }

    @Test
    void showcaseProfileExplicitlyOptsInToDemoIdentity() {
        final Properties properties = load("application-showcase.yaml");

        assertThat(properties.getProperty("showcase.demo-identity")).isEqualTo("true");
        assertThat(properties.getProperty("authorization.demo-policy.enabled")).isEqualTo("true");
    }

    private static Properties load(final String resource) {
        final YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new ClassPathResource(resource));
        final Properties properties = factory.getObject();
        assertThat(properties).isNotNull();
        return properties;
    }
}
