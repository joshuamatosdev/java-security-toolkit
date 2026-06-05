package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

/**
 * Cookie Policy Config test coverage.
 *
 * <p>Why this is important to test: credentialed CORS and cookie defaults can accidentally widen
 * browser access to protected routes.
 */
class CookiePolicyConfigTest {

  private final CookiePolicyConfig config = new CookiePolicyConfig();

  @Test
  void sessionCookieUsesTheEdgeSecurePolicy() {
    var properties =
        new EdgePerimeterProperties(null, new EdgePerimeterProperties.Cookie(true), null);
    var resolver = config.webSessionIdResolver(properties);
    var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("http://edge.local/api/documents"));

    resolver.setSessionId(exchange, "session-id");

    var cookie = exchange.getResponse().getCookies().getFirst("SESSION");
    assertThat(cookie).isNotNull();
    assertThat(cookie.isSecure()).isTrue();
    assertThat(cookie.isHttpOnly()).isTrue();
    assertThat(cookie.getSameSite()).isEqualTo("Lax");
  }

  @Test
  void sessionCookieCanOptOutOfSecureForPlainHttpLocalRuns() {
    var properties =
        new EdgePerimeterProperties(null, new EdgePerimeterProperties.Cookie(false), null);
    var resolver = config.webSessionIdResolver(properties);
    var exchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("http://edge.local/api/documents"));

    resolver.setSessionId(exchange, "session-id");

    var cookie = exchange.getResponse().getCookies().getFirst("SESSION");
    assertThat(cookie).isNotNull();
    assertThat(cookie.isSecure()).isFalse();
  }
}
