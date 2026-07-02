package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

/**
 * Binds the shipped configuration artifacts and proves they are internally consistent. The default
 * profile must not ship non-Secure cookies while HSTS pins HTTPS — a non-Secure session or CSRF
 * cookie under unconditional Strict-Transport-Security is self-contradictory. The plain-HTTP local
 * profile is the single, explicit place that relaxes cookie {@code Secure} and HSTS together.
 *
 * <p>Why this is important to test: credentialed CORS and cookie defaults can accidentally widen
 * browser access to protected routes.
 */
class ShippedConfigurationConsistencyTest {

  @Test
  void defaultProfileShipsSecureCookiesUnderUnconditionalHsts() throws IOException {
    EdgeProperties properties = bindEdge("application.yaml");

    assertThat(properties.cookie().secure()).isTrue();
    assertThat(properties.hsts().unconditional()).isTrue();
  }

  @Test
  void localProfileRelaxesCookieSecureAndHstsTogetherForPlainHttp() throws IOException {
    EdgeProperties properties = bindEdge("application-local.yaml");

    assertThat(properties.cookie().secure()).isFalse();
    assertThat(properties.hsts().unconditional()).isFalse();
  }

  private static EdgeProperties bindEdge(String yamlResource) throws IOException {
    StandardEnvironment environment = new StandardEnvironment();
    new YamlPropertySourceLoader()
        .load(yamlResource, new ClassPathResource(yamlResource))
        .forEach(environment.getPropertySources()::addLast);
    return Binder.get(environment).bind("edge", EdgeProperties.class).get();
  }
}
