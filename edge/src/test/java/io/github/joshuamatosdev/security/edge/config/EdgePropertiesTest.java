package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * Proves the cookie-secure default fails safe. The "defaults to true" promise must hold not only
 * when the whole {@code edge.cookie} block is absent, but also when the block is present with
 * {@code secure} omitted — the case a primitive field would silently bind to {@code false}.
 *
 * <p>Why this is important to test: credentialed CORS and cookie defaults can accidentally widen
 * browser access to protected routes.
 */
class EdgePropertiesTest {

  @Test
  void cookieSecureDefaultsToTrueWhenOmitted() {
    // Boot binds an omitted Boolean key to null; the record's default must turn that into true.
    assertThat(new EdgeProperties.Cookie(null).secure()).isTrue();
  }

  @Test
  void cookieSecureHonoursAnExplicitFalse() {
    assertThat(new EdgeProperties.Cookie(false).secure()).isFalse();
  }

  @Test
  void absentCookieBlockAlsoDefaultsSecureToTrue() {
    EdgeProperties properties = new EdgeProperties(null, null, null);
    assertThat(properties.cookie().secure()).isTrue();
  }

  @Test
  void hstsDefaultsToUnconditional() {
    EdgeProperties properties = new EdgeProperties(null, null, null);
    assertThat(properties.hsts().unconditional()).isTrue();
  }

  @Test
  void hstsUnconditionalHonoursAnExplicitFalse() {
    assertThat(new EdgeProperties.Hsts(false).unconditional()).isFalse();
  }

  @Test
  void identityIssuerDefaultsToReferenceIssuer() {
    EdgeProperties properties = new EdgeProperties(null, null, null);
    assertThat(properties.identity().issuerUri())
        .isEqualTo(EdgeProperties.DEFAULT_ISSUER_URI);
  }

  @Test
  void identityIssuerRejectsBlankExplicitIssuer() {
    assertThatThrownBy(() -> new EdgeProperties.Identity(" "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not be blank");
  }

  @Test
  void identityIssuerRejectsLeadingOrTrailingWhitespace() {
    assertThatThrownBy(() -> new EdgeProperties.Identity(" https://idp.acme.example/realms/demo"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not include leading or trailing whitespace");
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example/realms/demo "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not include leading or trailing whitespace");
  }

  @Test
  void identityIssuerRejectsControlCharacters() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example/realms/demo\u0000"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not contain control characters");
  }

  @Test
  void identityIssuerRejectsMalformedIssuer() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("not an issuer"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("absolute HTTP(S) URI");
  }

  @Test
  void identityIssuerRejectsInvalidExplicitPorts() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example:99999"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("valid HTTP(S) port");

    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example:"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("valid HTTP(S) port");
  }

  @Test
  void identityIssuerRejectsRemotePlainHttpIssuer() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("http://idp.acme.example"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must use HTTPS except for loopback");
  }

  @Test
  void identityIssuerAllowsLoopbackPlainHttpForLocalDevelopment() {
    assertThat(new EdgeProperties.Identity("http://localhost:8081/realms/demo").issuerUri())
        .isEqualTo("http://localhost:8081/realms/demo");
  }

  @Test
  void identityIssuerAllowsIpv6LoopbackPlainHttpForLocalDevelopment() {
    assertThat(new EdgeProperties.Identity("http://[::1]:8081/realms/demo").issuerUri())
        .isEqualTo("http://[::1]:8081/realms/demo");
  }

  @Test
  void identityIssuerRejectsUserInfoCredentials() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://userinfo@idp.acme.example"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include user-info credentials");
  }

  @Test
  void identityIssuerRejectsQueryAndFragmentComponents() {
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example/issuer?env=dev"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include query or fragment");
    assertThatThrownBy(() -> new EdgeProperties.Identity("https://idp.acme.example/issuer#fragment"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include query or fragment");
  }

  @Test
  void serviceJwtAudienceDefaultsToReferenceAudience() {
    EdgeProperties properties = new EdgeProperties(null, null, null);
    assertThat(properties.serviceJwt().audiences())
        .containsExactly(EdgeProperties.DEFAULT_SERVICE_AUDIENCE);
  }

  @Test
  void serviceJwtAudiencesRejectBlankEntries() {
    assertThatThrownBy(
            () ->
                new EdgeProperties.ServiceJwt(
                    java.util.List.of(EdgeProperties.DEFAULT_SERVICE_AUDIENCE, " ")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not contain blank entries");
  }

  @Test
  void serviceJwtAudiencesRejectLeadingOrTrailingWhitespace() {
    assertThatThrownBy(
            () ->
                new EdgeProperties.ServiceJwt(
                    java.util.List.of(EdgeProperties.DEFAULT_SERVICE_AUDIENCE + " ")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not include leading or trailing whitespace");
  }

  @Test
  void serviceJwtAudiencesRejectControlCharacters() {
    assertThatThrownBy(
            () ->
                new EdgeProperties.ServiceJwt(
                    java.util.List.of(EdgeProperties.DEFAULT_SERVICE_AUDIENCE + "\nforged")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not contain control characters");
  }
}
