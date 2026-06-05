package io.github.joshuamatosdev.security.edge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves CSRF is enforced on the browser plane and disabled on the service plane.
 *
 * <p>Browser plane: a mutating request without a CSRF token is rejected (403) even with a valid
 * session; supplying the token lets it through. Service plane: a tokenless mutating request is not
 * blocked by CSRF — it reaches routing (which rejects the method), proving the CSRF filter did not
 * short-circuit it. A bearer plane has no cookie to ride and no browser to forge from, so CSRF is
 * correctly absent.
 *
 * <p>Why this is important to test: the edge is the first externally reachable request boundary,
 * so regressions become observable access-control behavior.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class CsrfProtectionTest {

  @Autowired private WebTestClient webClient;

  @Test
  void safeBrowserRequestMaterializesCsrfCookieForSpa() {
    webClient
        .mutateWith(mockOAuth2Login())
        .get()
        .uri("/api/documents")
        .exchange()
        .expectStatus()
        .isOk()
        .expectHeader()
        .value(
            HttpHeaders.SET_COOKIE,
            setCookie ->
                assertThat(setCookie)
                    .as("first safe browser request must issue an XSRF-TOKEN cookie")
                    .contains("XSRF-TOKEN="));
  }

  @Test
  void browserMutationWithoutCsrfTokenIsForbidden() {
    webClient
        .mutateWith(mockOAuth2Login())
        .post()
        .uri("/api/documents")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void browserMutationWithCsrfTokenSucceeds() {
    webClient
        .mutateWith(mockOAuth2Login())
        .mutateWith(csrf())
        .post()
        .uri("/api/documents")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void browserDeleteMutationWithCsrfTokenSucceeds() {
    webClient
        .mutateWith(mockOAuth2Login())
        .mutateWith(csrf())
        .delete()
        .uri("/api/documents/123")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void serviceMutationIsNotBlockedByCsrf() {
    // The service plane disables CSRF. A tokenless POST therefore is not 403'd by a CSRF filter;
    // it passes the security chain and reaches routing, which has no POST mapping -> 405. The
    // falsifiable claim is precisely "not blocked by CSRF", i.e. not 403.
    webClient
        .mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_service")))
        .post()
        .uri("/api/service/reports")
        .exchange()
        .expectStatus()
        .value(
            status ->
                assertThat(status)
                    .as("service plane is CSRF-exempt: a tokenless POST is not rejected by CSRF")
                    .isNotEqualTo(HttpStatus.FORBIDDEN.value()));
  }
}
