package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Proves PKCE is on every authorization request. Hitting the client authorization endpoint produces
 * a redirect to the IdP whose query carries a {@code code_challenge} and {@code
 * code_challenge_method=S256} — the binding that makes a stolen authorization code useless to anyone
 * without the verifier this public client holds.
 */
@SpringBootTest
@AutoConfigureWebTestClient
class PkceAuthorizationRequestTest {

  @Autowired private WebTestClient webClient;

  @Test
  void authorizationRequestCarriesPkceChallenge() {
    webClient
        .get()
        .uri("/oauth2/authorization/idp")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .value(
            "Location",
            location -> {
              assertThat(location)
                  .as("the authorization redirect targets the configured IdP authorize endpoint")
                  .startsWith("https://idp.acme.example/oauth2/authorize");
              assertThat(location)
                  .as("PKCE adds a code_challenge bound to the per-request verifier")
                  .contains("code_challenge=");
              assertThat(location)
                  .as("the challenge method must be SHA-256, not plain")
                  .contains("code_challenge_method=S256");
            });
  }
}
