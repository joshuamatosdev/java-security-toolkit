package io.github.joshuamatosdev.security.edge;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockOAuth2Login;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves the browser-plane route map: deny-by-default, role-gated admin surface, the
 * narrow-before-broad audit-export exception, and actuator lockdown. The status code is the
 * observable — a request that reaches a controller returns 200; one the route map rejects is
 * short-circuited (302 to login for anonymous, 403 for an authenticated-but-unauthorized caller)
 * before any handler runs.
 *
 * <p>Why this is important to test: the edge is the first externally reachable request boundary,
 * so regressions become observable access-control behavior.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class RouteAuthorizationTest {

  private static final String LOGIN_REDIRECT = "/oauth2/authorization/idp";

  @Autowired private WebTestClient webClient;

  private static SimpleGrantedAuthority role(String authority) {
    return new SimpleGrantedAuthority(authority);
  }

  @Test
  void publicStatusIsReachableAnonymously() {
    webClient.get().uri("/api/public/status").exchange().expectStatus().isOk();
  }

  @Test
  void actuatorHealthIsReachableAnonymously() {
    webClient.get().uri("/actuator/health").exchange().expectStatus().isOk();
  }

  @Test
  void publicStatusOnlyPermitsGet() {
    webClient
        .mutateWith(mockOAuth2Login())
        .mutateWith(csrf())
        .post()
        .uri("/api/public/status")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void actuatorHealthOnlyPermitsGet() {
    webClient
        .mutateWith(mockOAuth2Login())
        .mutateWith(csrf())
        .post()
        .uri("/actuator/health")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void anonymousRequestToProtectedRouteRedirectsToLogin() {
    webClient
        .get()
        .uri("/api/documents")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .value(
            "Location",
            location ->
                assertThat(location)
                    .as("anonymous access to a protected route starts the OIDC login round-trip")
                    .contains(LOGIN_REDIRECT));
  }

  @Test
  void authenticatedSessionReachesGenericProtectedRoute() {
    webClient
        .mutateWith(mockOAuth2Login())
        .get()
        .uri("/api/documents")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void authenticatedSessionCannotReachUnmatchedBrowserRoute() {
    webClient
        .mutateWith(mockOAuth2Login())
        .get()
        .uri("/api/not-a-mapped-route")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void adminRouteForbiddenForNonAdminSession() {
    webClient
        .mutateWith(mockOAuth2Login())
        .get()
        .uri("/api/admin/dashboard")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void adminRouteAllowedForAdminRole() {
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_admin")))
        .get()
        .uri("/api/admin/dashboard")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void auditExportReachableByAuditorThroughNarrowException() {
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_auditor")))
        .get()
        .uri("/api/admin/audit-export")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void auditorCannotReachBroadAdminSurface() {
    // The auditor's grant is scoped to the narrow exception only; the broad admin gate that
    // follows it requires ROLE_admin. This is the first-match-wins ordering proof.
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_auditor")))
        .get()
        .uri("/api/admin/dashboard")
        .exchange()
        .expectStatus()
        .isForbidden();
  }

  @Test
  void adminAlsoReachesTheAuditExportException() {
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_admin")))
        .get()
        .uri("/api/admin/audit-export")
        .exchange()
        .expectStatus()
        .isOk();
  }

  @Test
  void nonExposedActuatorEndpointIsDeniedForAuthenticatedCaller() {
    // /actuator/env is not in the exposure list AND is covered by the /actuator/** denyAll rule.
    // An authenticated caller is denied (403) by the route map before endpoint resolution — the
    // belt-and-suspenders half of the actuator lockdown.
    webClient
        .mutateWith(mockOAuth2Login().authorities(role("ROLE_admin")))
        .get()
        .uri("/actuator/env")
        .exchange()
        .expectStatus()
        .isForbidden();
  }
}
