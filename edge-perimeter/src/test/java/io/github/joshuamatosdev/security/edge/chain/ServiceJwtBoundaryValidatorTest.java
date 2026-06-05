package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

/**
 * Service Jwt Boundary Validator test coverage.
 *
 * <p>Why this is important to test: browser sessions and service JWTs are separate credential
 * planes, and validator drift could accept the wrong token.
 */
class ServiceJwtBoundaryValidatorTest {

  private static final String ISSUER = EdgePerimeterProperties.DEFAULT_ISSUER_URI;
  private static final String AUDIENCE = EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE;

  private Jwt jwt(String issuer, Object audience) {
    return new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(300),
        Map.of("alg", "RS256"),
        Map.of(
            JwtClaimNames.ISS,
            issuer,
            JwtClaimNames.SUB,
            "service-client",
            JwtClaimNames.AUD,
            audience));
  }

  @Test
  void acceptsTrustedIssuerAndAudienceList() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, List.of(AUDIENCE))).hasErrors()).isFalse();
  }

  @Test
  void acceptsTrustedIssuerAndStringAudience() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, AUDIENCE)).hasErrors()).isFalse();
  }

  @Test
  void rejectsWrongIssuer() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt("https://other-idp.example", List.of(AUDIENCE))).hasErrors())
        .isTrue();
  }

  @Test
  void rejectsTokenForAnotherAudience() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, List.of("other-service"))).hasErrors()).isTrue();
  }

  @Test
  void rejectsMalformedAudienceListEvenWhenItContainsAcceptedAudience() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, List.of(AUDIENCE, 7))).hasErrors()).isTrue();
  }

  @Test
  void rejectsAudienceListWithBlankOrWhitespacePaddedEntryEvenWhenItContainsAcceptedAudience() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, List.of(AUDIENCE, " "))).hasErrors()).isTrue();
    assertThat(validator.validate(jwt(ISSUER, List.of(AUDIENCE, " other-service"))).hasErrors())
        .isTrue();
  }

  @Test
  void rejectsAudienceListWithControlCharacterEntryEvenWhenItContainsAcceptedAudience() {
    var validator = ServiceApiSecurityChainConfig.serviceJwtBoundaryValidator(ISSUER, List.of(AUDIENCE));

    assertThat(validator.validate(jwt(ISSUER, List.of(AUDIENCE, "other-service\nforged"))).hasErrors())
        .isTrue();
  }
}
