package io.github.joshuamatosdev.security.edge.config;

import java.net.URI;

/**
 * Boundary predicates shared by the credentialed CORS allow-list and the issuer-URI policy.
 *
 * <p>Both startup guards must enforce the same rules — loopback is the only plain-HTTP exception,
 * an explicit port must be a real HTTP(S) port, and control characters never enter a policy value.
 * Keeping the predicates in one place means the two guards cannot drift apart.
 */
final class UriValidation {

  private UriValidation() {}

  static boolean isLoopbackHost(String host) {
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host);
  }

  /**
   * Accepts an absent port ({@code -1}); a written port must parse and stay in range. {@link URI}
   * reports a trailing-colon authority ({@code host:}) as "no port", so that malformed shape is
   * rejected off the raw authority instead.
   */
  static boolean hasValidExplicitHttpPort(URI parsed) {
    String rawAuthority = parsed.getRawAuthority();
    int port = parsed.getPort();
    return (port == -1 || port > 0) && port <= 65535 && (rawAuthority == null || !rawAuthority.endsWith(":"));
  }

  static boolean containsControlCharacter(String value) {
    return value.chars().anyMatch(Character::isISOControl);
  }
}
