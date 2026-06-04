package io.github.joshuamatosdev.security.edge.chain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;

/**
 * Adds PKCE to every OAuth2 authorization request the browser plane initiates.
 *
 * <p>The BFF is registered as a public client (no client secret). Authorization-Code without PKCE
 * would let anyone who intercepts the authorization code (redirect logs, a malicious app holding
 * the redirect URI) redeem it for tokens. PKCE binds the code to a per-request {@code code_verifier}
 * the client never transmits in the front channel — the authorization server only ever sees the
 * SHA-256 {@code code_challenge}, and the token exchange must present the matching verifier. A
 * stolen code is then useless without the verifier held only by this BFF instance.
 *
 * <p>Spring Boot 3.x does not expose {@code ClientSettings.requireProofKey} through configuration
 * properties for a reactive public client, so the PKCE customizer is applied directly to the
 * authorization-request resolver.
 */
@Configuration
public class PkceRelaySupport {

  @Bean
  public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    var resolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
    resolver.setAuthorizationRequestCustomizer(
        OAuth2AuthorizationRequestCustomizers.withPkce());
    return resolver;
  }
}
