package io.github.joshuamatosdev.security.edge.config;

import io.github.joshuamatosdev.security.edge.chain.RouteAuthorities;
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
 * allow wildcard, opaque, or insecure non-loopback origins: those origins let untrusted or
 * network-tamperable browser contexts script authenticated requests against the BFF — exactly the
 * session-riding CSRF defends against. The constructor fails the application at startup rather than
 * letting that misconfiguration deploy.
 *
 * <p>The allowed header list is intentionally short. {@code Content-Type} for JSON bodies,
 * {@code X-XSRF-TOKEN} for the CSRF double-submit echo, {@code X-Requested-With} for legacy
 * XHR marking. Every additional allowed header widens what a cross-origin attacker can vary.
 *
 * <p>Why this exists: CORS and cookie policy are credentialed browser trust decisions, so their
 * allow-lists need to be explicit and auditable.
 */
@Configuration
public class CorsAllowListConfig {

  private static final List<String> GET_ONLY_METHODS = List.of("GET");
  private static final List<String> DOCUMENT_METHODS = List.of("GET", "POST", "DELETE");

  @Bean
  public CorsConfigurationSource corsConfigurationSource(EdgePerimeterProperties properties) {
    var origins = properties.cors().allowedOrigins();

    if (origins.stream().anyMatch(origin -> origin == null || origin.isBlank())) {
      throw new IllegalStateException(
          "Credentialed CORS origins must not contain blank entries.");
    }
    if (origins.stream().anyMatch(origin -> !origin.equals(origin.strip()))) {
      throw new IllegalStateException(
          "Credentialed CORS origins must not include leading or trailing whitespace.");
    }
    if (origins.stream().anyMatch(CorsAllowListConfig::containsControlCharacter)) {
      throw new IllegalStateException(
          "Credentialed CORS origins must not contain control characters.");
    }
    origins.forEach(CorsAllowListConfig::validateCredentialedOrigin);

    // Browser-plane route truth lives once, in RouteAuthorities — registering from the same
    // constants the authorization rules use means the CORS surface cannot drift from the routes.
    var source = new UrlBasedCorsConfigurationSource();
    for (String path : RouteAuthorities.PUBLIC_PATHS) {
      source.registerCorsConfiguration(path, credentialedCors(origins, GET_ONLY_METHODS));
    }
    for (String path : RouteAuthorities.DOCUMENT_PATHS) {
      source.registerCorsConfiguration(path, credentialedCors(origins, DOCUMENT_METHODS));
    }
    for (String path : RouteAuthorities.ADMIN_PATHS) {
      source.registerCorsConfiguration(path, credentialedCors(origins, GET_ONLY_METHODS));
    }
    // The actuator is not a RouteAuthorities surface (its permit/deny split lives in the browser
    // chain); only its read-only health/info exposure is reachable, so GET-only CORS is correct.
    source.registerCorsConfiguration("/actuator/**", credentialedCors(origins, GET_ONLY_METHODS));
    return source;
  }

  private static CorsConfiguration credentialedCors(List<String> origins, List<String> methods) {
    var config = new CorsConfiguration();
    config.setAllowedOrigins(origins);
    config.setAllowedMethods(methods);
    config.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN", "X-Requested-With"));
    config.setAllowCredentials(true);
    config.setMaxAge(600L);
    return config;
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
    if (!hasValidExplicitHttpPort(parsed)) {
      throw new IllegalStateException(
          "Credentialed CORS origins must include a valid HTTP(S) port when a port is explicit: "
              + origin);
    }
    if ("http".equalsIgnoreCase(scheme) && !isLoopbackHost(parsed.getHost())) {
      throw new IllegalStateException(
          "Credentialed CORS origins must use HTTPS except for loopback local development: "
              + origin);
    }
  }

  private static boolean isLoopbackHost(String host) {
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host);
  }

  private static boolean hasValidExplicitHttpPort(URI parsed) {
    String rawAuthority = parsed.getRawAuthority();
    int port = parsed.getPort();
    return (port == -1 || port > 0) && port <= 65535 && (rawAuthority == null || !rawAuthority.endsWith(":"));
  }

  private static boolean containsControlCharacter(String value) {
    return value.chars().anyMatch(Character::isISOControl);
  }
}
