package io.github.joshuamatosdev.security.edge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves the service plane: a stateless bearer-JWT resource server under {@code /api/service/**}.
 * The 401-vs-403 split is the authn-vs-authz boundary — no token is unauthenticated (401 with a
 * Bearer challenge), a valid token without the role is unauthorized (403), the right role passes.
 *
 * <p>Why this is important to test: the edge is the first externally reachable request boundary,
 * so regressions become observable access-control behavior.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class ServiceApiAuthorizationTest {

  @Autowired private WebTestClient webClient;

  private static SimpleGrantedAuthority role(String authority) {
    return new SimpleGrantedAuthority(authority);
  }

  @Test
  void serviceReportRequiresAToken() {
    webClient
        .get()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .isUnauthorized()
        .expectHeader()
        .value(
            "WWW-Authenticate",
            challenge ->
                assertThat(challenge)
                    .as("a resource server challenges a missing token with Bearer")
                    .startsWith("Bearer"));
  }

  @Test
  void serviceReportRejectsNonJwtAuthenticationEvenWithServiceRole() {
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_service")))
        .get()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void serviceReportForbiddenWithoutServiceRole() {
    webClient
        .mutateWith(mockJwt().authorities(role("ROLE_other")))
        .get()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void unknownServiceRouteIsDeniedEvenWithAuthenticatedToken() {
    webClient
        .mutateWith(mockJwt().authorities(role("ROLE_other")))
        .get()
        .uri("/api/service/unknown")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void serviceReportAllowedWithServiceRole() {
    webClient
        .mutateWith(mockJwt().authorities(role("ROLE_service")))
        .get()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void serviceReportDoesNotMintBrowserCookies() {
    webClient
        .mutateWith(mockJwt().authorities(role("ROLE_service")))
        .get()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .isOk()
        .expectHeader()
        .doesNotExist(HttpHeaders.SET_COOKIE);
  }
}
