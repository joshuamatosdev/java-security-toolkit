package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;

/**
 * Unit-level proof of the credentialed-CORS safety guard. A credentialed policy that allowed
 * {@code *} would let any website script authenticated requests against the BFF, so the
 * configuration must refuse to build with a wildcard origin — at startup, not at request time.
 *
 * <p>Why this is important to test: credentialed CORS and cookie defaults can accidentally widen
 * browser access to protected routes.
 */
class CorsAllowListTest {

  private final CorsAllowListConfig config = new CorsAllowListConfig();

  private static EdgePerimeterProperties withOrigins(String... origins) {
    return new EdgePerimeterProperties(
        new EdgePerimeterProperties.Cors(List.of(origins)), null, null);
  }

  @Test
  void wildcardOriginIsRejectedAtStartup() {
    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("*")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Credentialed CORS cannot use '*'");
  }

  @Test
  void opaqueNullOriginIsRejectedAtStartup() {
    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("null")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("opaque 'null' origin");
  }

  @Test
  void originWithPathIsRejectedAtStartup() {
    assertThatThrownBy(
            () -> config.corsConfigurationSource(withOrigins("https://app.acme.example/path")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("absolute HTTP(S) origins");
  }

  @Test
  void nonHttpOriginIsRejectedAtStartup() {
    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("file://local-app")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("absolute HTTP(S) origins");
  }

  @Test
  void originWithInvalidExplicitPortIsRejectedAtStartup() {
    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("https://app.acme.example:99999")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("valid HTTP(S) port");

    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("https://app.acme.example:")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("valid HTTP(S) port");
  }

  @Test
  void insecureRemoteHttpOriginIsRejectedAtStartup() {
    assertThatThrownBy(() -> config.corsConfigurationSource(withOrigins("http://app.acme.example")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must use HTTPS except for loopback");
  }

  @Test
  void blankOriginEntryIsRejectedAtStartup() {
    assertThatThrownBy(
            () -> config.corsConfigurationSource(withOrigins("https://app.acme.example", " ")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must not contain blank entries");
  }

  @Test
  void originWithLeadingOrTrailingWhitespaceIsRejectedAtStartup() {
    assertThatThrownBy(
            () -> config.corsConfigurationSource(withOrigins(" https://app.acme.example")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must not include leading or trailing whitespace");
  }

  @Test
  void originWithControlCharactersIsRejectedAtStartup() {
    assertThatThrownBy(
            () -> config.corsConfigurationSource(withOrigins("https://app.acme.example\u0000")))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must not contain control characters");
  }

  @Test
  void explicitOriginBuildsACredentialedAllowList() {
    CorsConfigurationSource source =
        config.corsConfigurationSource(withOrigins("https://app.acme.example"));

    MockServerWebExchange exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/api/documents"));
    CorsConfiguration resolved = source.getCorsConfiguration(exchange);

    assertThat(resolved).isNotNull();
    assertThat(resolved.getAllowedOrigins()).containsExactly("https://app.acme.example");
    assertThat(resolved.getAllowCredentials()).isTrue();
  }

  @Test
  void loopbackHttpOriginBuildsACredentialedAllowListForLocalDevelopment() {
    CorsConfigurationSource source = config.corsConfigurationSource(withOrigins("http://localhost:5173"));

    MockServerWebExchange exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/api/documents"));
    CorsConfiguration resolved = source.getCorsConfiguration(exchange);

    assertThat(resolved).isNotNull();
    assertThat(resolved.getAllowedOrigins()).containsExactly("http://localhost:5173");
    assertThat(resolved.getAllowCredentials()).isTrue();
  }

  @Test
  void servicePlaneDoesNotResolveCorsConfiguration() {
    CorsConfigurationSource source =
        config.corsConfigurationSource(withOrigins("https://app.acme.example"));

    MockServerWebExchange exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/api/service/reports"));

    assertThat(source.getCorsConfiguration(exchange)).isNull();
  }
}
