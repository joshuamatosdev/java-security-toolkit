package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

class OidcIdTokenBoundaryValidatorTest {

  private static final String ISSUER = EdgePerimeterProperties.DEFAULT_ISSUER_URI;
  private static final String CLIENT_ID = "edge-bff";

  private ClientRegistration clientRegistrationWithoutIssuerMetadata() {
    return ClientRegistration.withRegistrationId("idp")
        .clientId(CLIENT_ID)
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/idp")
        .scope("openid", "profile")
        .authorizationUri("https://idp.acme.example/oauth2/authorize")
        .tokenUri("https://idp.acme.example/oauth2/token")
        .jwkSetUri("https://idp.acme.example/oauth2/jwks")
        .userInfoUri("https://idp.acme.example/oauth2/userinfo")
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .build();
  }

  private Jwt idToken(String issuer) {
    Instant issuedAt = Instant.now();
    return new Jwt(
        "id-token-value",
        issuedAt,
        issuedAt.plusSeconds(300),
        Map.of("alg", "RS256"),
        Map.of(
            IdTokenClaimNames.ISS,
            issuer,
            IdTokenClaimNames.SUB,
            "user-123",
            IdTokenClaimNames.AUD,
            List.of(CLIENT_ID)));
  }

  @Test
  void acceptsTheTrustedIssuerWithoutClientIssuerMetadata() {
    ClientRegistration registration = clientRegistrationWithoutIssuerMetadata();
    var validator = BrowserSecurityChainConfig.oidcIdTokenValidatorFactory(ISSUER).apply(registration);

    assertThat(registration.getProviderDetails().getIssuerUri()).isNull();
    assertThat(validator.validate(idToken(ISSUER)).hasErrors()).isFalse();
  }

  @Test
  void rejectsWrongIssuerWithoutClientIssuerMetadata() {
    ClientRegistration registration = clientRegistrationWithoutIssuerMetadata();
    var validator = BrowserSecurityChainConfig.oidcIdTokenValidatorFactory(ISSUER).apply(registration);

    assertThat(registration.getProviderDetails().getIssuerUri()).isNull();
    assertThat(validator.validate(idToken("https://other-idp.example")).hasErrors()).isTrue();
  }
}
