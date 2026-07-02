package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class ExplicitHttpPortValidationTest {

  @Test
  void identityIssuerRejectsReservedPortZero() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example:0"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("valid HTTP(S) port");
  }

  @Test
  void credentialedCorsOriginRejectsReservedPortZero() {
    EdgeProperties properties =
        new EdgeProperties(
            new EdgeProperties.Cors(List.of("https://app.acme.example:0")),
            null,
            null);

    assertThatThrownBy(() -> new CorsAllowListConfig().corsConfigurationSource(properties))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("valid HTTP(S) port");
  }
}
