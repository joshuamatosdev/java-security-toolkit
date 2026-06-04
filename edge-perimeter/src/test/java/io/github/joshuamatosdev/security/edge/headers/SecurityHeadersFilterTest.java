package io.github.joshuamatosdev.security.edge.headers;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Unit-level proof of the one conditional header, HSTS. The always-on headers are asserted once;
 * the matrix that matters is when {@code Strict-Transport-Security} is emitted: unconditionally
 * when configured, on a forwarded HTTPS proto, and never on plain HTTP by default.
 */
class SecurityHeadersFilterTest {

  /** A chain that completes the response so {@code beforeCommit} hooks fire. */
  private static final WebFilterChain COMPLETING_CHAIN =
      exchange -> exchange.getResponse().setComplete();

  private static HttpHeaders runFilter(SecurityHeadersFilter filter, MockServerWebExchange exchange) {
    filter.filter(exchange, COMPLETING_CHAIN).block();
    return exchange.getResponse().getHeaders();
  }

  private static MockServerWebExchange plainHttpExchange() {
    return MockServerWebExchange.from(MockServerHttpRequest.get("http://edge.local/x"));
  }

  @Test
  void alwaysOnHeadersAreSetRegardlessOfTransport() {
    HttpHeaders headers =
        runFilter(new SecurityHeadersFilter(false), plainHttpExchange());

    assertThat(headers.getFirst(SecurityHeadersFilter.X_CONTENT_TYPE_OPTIONS_HEADER))
        .isEqualTo(SecurityHeadersFilter.X_CONTENT_TYPE_OPTIONS_VALUE);
    assertThat(headers.getFirst(SecurityHeadersFilter.X_FRAME_OPTIONS_HEADER))
        .isEqualTo(SecurityHeadersFilter.X_FRAME_OPTIONS_VALUE);
    assertThat(headers.getFirst(SecurityHeadersFilter.CONTENT_SECURITY_POLICY_HEADER))
        .isEqualTo(SecurityHeadersFilter.CONTENT_SECURITY_POLICY_VALUE);
    assertThat(headers.getFirst(SecurityHeadersFilter.X_XSS_PROTECTION_HEADER))
        .isEqualTo(SecurityHeadersFilter.X_XSS_PROTECTION_VALUE);
  }

  @Test
  void hstsAbsentOnPlainHttpWhenNotUnconditional() {
    HttpHeaders headers =
        runFilter(new SecurityHeadersFilter(false), plainHttpExchange());

    assertThat(headers.getFirst(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_HEADER)).isNull();
  }

  @Test
  void hstsEmittedUnconditionallyWhenConfigured() {
    HttpHeaders headers =
        runFilter(new SecurityHeadersFilter(true), plainHttpExchange());

    assertThat(headers.getFirst(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_HEADER))
        .isEqualTo(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_VALUE);
  }

  @Test
  void hstsEmittedWhenForwardedProtoIsHttps() {
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("http://edge.local/x").header("X-Forwarded-Proto", "https"));

    HttpHeaders headers = runFilter(new SecurityHeadersFilter(false), exchange);

    assertThat(headers.getFirst(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_HEADER))
        .isEqualTo(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_VALUE);
  }

  @Test
  void firstForwardedProtoValueDecidesHsts() {
    // A comma-joined chain lists the client-facing proto first; an http client edge must NOT get
    // HSTS just because an internal hop was https.
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("http://edge.local/x")
                .header("X-Forwarded-Proto", "http, https"));

    HttpHeaders headers = runFilter(new SecurityHeadersFilter(false), exchange);

    assertThat(headers.getFirst(SecurityHeadersFilter.STRICT_TRANSPORT_SECURITY_HEADER)).isNull();
  }
}
