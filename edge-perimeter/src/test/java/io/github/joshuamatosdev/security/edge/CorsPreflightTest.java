package io.github.joshuamatosdev.security.edge;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves the credentialed CORS allow-list at the wire level. A preflight from an allow-listed origin
 * is answered with the echoed origin plus {@code Allow-Credentials: true}; a preflight from any
 * other origin is rejected (403). The {@code *}-with-credentials misconfiguration is proven impossible
 * by the startup guard, unit-tested in {@code config.CorsAllowListTest}.
 *
 * <p>The client is rebound to an absolute base URL because Spring's CORS same-origin check
 * ({@code CorsUtils.isSameOrigin}) asserts the request URI has a non-null host; the default
 * application-context-bound client synthesizes hostless relative URIs, which a real HTTP request
 * never does.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class CorsPreflightTest {

  private static final String ALLOWED_ORIGIN = "https://app.acme.example";
  private static final String FOREIGN_ORIGIN = "https://evil.example";

  @Autowired private WebTestClient autowiredClient;

  private WebTestClient webClient;

  @BeforeEach
  void useAbsoluteBaseUrl() {
    webClient = autowiredClient.mutate().baseUrl("http://localhost").build();
  }

  @Test
  void preflightFromAllowedOriginIsAccepted() {
    webClient
        .options()
        .uri("/api/documents")
        .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .exchange()
        .expectStatus()
        .isOk()
        .expectHeader()
        .valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, ALLOWED_ORIGIN)
        .expectHeader()
        .valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
  }

  @Test
  void preflightFromForeignOriginIsRejected() {
    webClient
        .options()
        .uri("/api/documents")
        .header(HttpHeaders.ORIGIN, FOREIGN_ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .exchange()
        .expectStatus()
        .isForbidden()
        .expectHeader()
        .doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
  }

  @Test
  void servicePlaneHasNoCorsSurface() {
    webClient
        .options()
        .uri("/api/service/reports")
        .header(HttpHeaders.ORIGIN, ALLOWED_ORIGIN)
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .exchange()
        .expectStatus()
        .is4xxClientError()
        .expectHeader()
        .doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)
        .expectHeader()
        .doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
  }
}
