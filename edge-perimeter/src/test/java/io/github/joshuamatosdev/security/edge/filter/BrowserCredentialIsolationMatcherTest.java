package io.github.joshuamatosdev.security.edge.filter;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.edge.chain.ServiceApiSecurityChainConfig;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Browser Credential Isolation Matcher test coverage.
 *
 * <p>Why this is important to test: browser-supplied bearer headers must not leak into service
 * authorization decisions.
 */
class BrowserCredentialIsolationMatcherTest {

  private final BrowserCredentialIsolationFilter filter = new BrowserCredentialIsolationFilter();

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/api/service",
        "/api/service/",
        "/api/service;v=1",
        "/api/service;v=1/reports",
        "/api/service/reports",
        "/api/serviceish",
        "/api/service%2Freports",
        "/api/service%2freports"
      })
  void authorizationHeaderIsPreservedExactlyWhenServiceSecurityChainMatches(String path) {
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get(path)
                .header(HttpHeaders.AUTHORIZATION, "Bearer candidate-token"));

    boolean serviceChainMatches =
        ServerWebExchangeMatchers.pathMatchers(ServiceApiSecurityChainConfig.SERVICE_MATCHER)
            .matches(exchange)
            .block()
            .isMatch();

    ServerHttpRequest downstream = runAndCaptureDownstreamRequest(exchange);
    boolean authorizationPreserved =
        downstream.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);

    assertThat(authorizationPreserved)
        .as("filter and service security matcher must agree for path %s", path)
        .isEqualTo(serviceChainMatches);
  }

  private ServerHttpRequest runAndCaptureDownstreamRequest(MockServerWebExchange exchange) {
    AtomicReference<ServerHttpRequest> captured = new AtomicReference<>();
    WebFilterChain chain =
        (ServerWebExchange ex) -> {
          captured.set(ex.getRequest());
          return Mono.empty();
        };
    filter.filter(exchange, chain).block();
    return captured.get();
  }
}
