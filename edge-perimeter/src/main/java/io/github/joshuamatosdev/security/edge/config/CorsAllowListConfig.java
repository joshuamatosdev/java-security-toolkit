package io.github.joshuamatosdev.security.edge.config;

import java.net.URI;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * Credentialed CORS allow-list for the browser plane.
 *
 * <p>The configuration is credentialed ({@code allowCredentials=true}) because the SPA sends the
 * session cookie and the {@code X-XSRF-TOKEN} header. A credentialed policy must therefore never
 * allow wildcard or opaque origins: a wildcard or {@code null} origin plus credentials lets
 * untrusted browser contexts script authenticated requests against the BFF — exactly the
 * session-riding CSRF defends against. The constructor fails the application at startup rather than
 * letting that misconfiguration deploy.
 *
 * <p>The allowed header list is intentionally short. {@code Content-Type} for JSON bodies,
 * {@code X-XSRF-TOKEN} for the CSRF double-submit echo, {@code X-Requested-With} for legacy
 * XHR marking. Every additional allowed header widens what a cross-origin attacker can vary.
 */
@Configuration
public class CorsAllowListConfig {

  private static final String[] BROWSER_CORS_PATHS = {
    "/api/public/**", "/api/documents/**", "/api/admin/**", "/actuator/**"
  };

  @Bean
  public CorsConfigurationSource corsConfigurationSource(EdgePerimeterProperties properties) {
    var origins =
        properties.cors().allowedOrigins().stream()
            .map(String::trim)
            .filter(origin -> !origin.isBlank())
            .toList();

    origins.forEach(CorsAllowListConfig::validateCredentialedOrigin);

    var config = new CorsConfiguration();
    config.setAllowedOrigins(origins);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN", "X-Requested-With"));
    config.setAllowCredentials(true);
    config.setMaxAge(600L);

    var source = new UrlBasedCorsConfigurationSource();
    for (String path : BROWSER_CORS_PATHS) {
      source.registerCorsConfiguration(path, config);
    }
    return source;
  }

  private static void validateCredentialedOrigin(String origin) {
    if ("*".equals(origin)) {
      throw new IllegalStateException(
          "Credentialed CORS cannot use '*'. Configure explicit frontend origins.");
    }
    if ("null".equalsIgnoreCase(origin)) {
      throw new IllegalStateException(
          "Credentialed CORS cannot allow the opaque 'null' origin.");
    }

    URI parsed;
    try {
      parsed = URI.create(origin);
    } catch (IllegalArgumentException ex) {
      throw new IllegalStateException(
          "Credentialed CORS origins must be absolute HTTP(S) origins: " + origin, ex);
    }

    String scheme = parsed.getScheme();
    boolean httpScheme = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    boolean originOnly =
        parsed.getHost() != null
            && parsed.getRawUserInfo() == null
            && (parsed.getRawPath() == null || parsed.getRawPath().isEmpty())
            && parsed.getRawQuery() == null
            && parsed.getRawFragment() == null;
    if (!httpScheme || !originOnly) {
      throw new IllegalStateException(
          "Credentialed CORS origins must be absolute HTTP(S) origins: " + origin);
    }
  }
}
