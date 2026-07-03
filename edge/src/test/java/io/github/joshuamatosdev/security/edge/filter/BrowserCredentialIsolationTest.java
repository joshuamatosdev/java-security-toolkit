package io.github.joshuamatosdev.security.edge.filter;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Unit-level proof of plane separation: the {@code Authorization} header is stripped on the browser
 * plane (where the credential is a session cookie) and preserved on the service plane (whose whole
 * contract is to accept bearer tokens). A capturing chain records the request the next filter would
 * actually observe.
 *
 * <p>Why this is important to test: browser-supplied bearer headers must not leak into service
 * authorization decisions.
 */
@ExtendWith(OutputCaptureExtension.class)
class BrowserCredentialIsolationTest {

  private final BrowserCredentialIsolationFilter filter = new BrowserCredentialIsolationFilter();

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

  @Test
  void browserPlaneStripsInboundAuthorizationHeader() {
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/documents")
                .header(HttpHeaders.AUTHORIZATION, "Bearer smuggled-service-token"));

    ServerHttpRequest downstream = runAndCaptureDownstreamRequest(exchange);

    assertThat(downstream.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION))
        .as("a browser-plane request must not carry a bearer token to downstream filters")
        .isFalse();
  }

  @Test
  void servicePlanePreservesInboundAuthorizationHeader() {
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/service/reports")
                .header(HttpHeaders.AUTHORIZATION, "Bearer legitimate-service-token"));

    ServerHttpRequest downstream = runAndCaptureDownstreamRequest(exchange);

    assertThat(downstream.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .as("the service plane's credential is the bearer token; it must reach the resource server")
        .isEqualTo("Bearer legitimate-service-token");
  }

  @Test
  void servicePlaneBarePrefixPreservesInboundAuthorizationHeader() {
    // The service security chain's matcher is /api/service/** , which owns the bare /api/service
    // (no trailing slash) too. The isolation filter must agree, or it strips the credential of a
    // request the service plane will then try to authenticate. The two predicates must be identical.
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/api/service")
                .header(HttpHeaders.AUTHORIZATION, "Bearer legitimate-service-token"));

    ServerHttpRequest downstream = runAndCaptureDownstreamRequest(exchange);

    assertThat(downstream.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .as("the bare /api/service prefix is service-plane; its bearer must survive the filter")
        .isEqualTo("Bearer legitimate-service-token");
  }

  @Test
  void browserPlaneCredentialStripLogUsesRawPathWithoutDecodedControlCharacters(
      CapturedOutput output) {
    MockServerWebExchange exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.method(
                    HttpMethod.GET, URI.create("https://edge.example/api/documents/%0Aforged"))
                .header(HttpHeaders.AUTHORIZATION, "Bearer smuggled-service-token"));

    runAndCaptureDownstreamRequest(exchange);

    assertThat(output.getAll())
        .contains("path=/api/documents/%0Aforged")
        .doesNotContain("path=/api/documents/\nforged");
  }
}
