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
class EdgePerimeterPropertiesTest {

  @Test
  void cookieSecureDefaultsToTrueWhenOmitted() {
    // Boot binds an omitted Boolean key to null; the record's default must turn that into true.
    assertThat(new EdgePerimeterProperties.Cookie(null).secure()).isTrue();
  }

  @Test
  void cookieSecureHonoursAnExplicitFalse() {
    assertThat(new EdgePerimeterProperties.Cookie(false).secure()).isFalse();
  }

  @Test
  void absentCookieBlockAlsoDefaultsSecureToTrue() {
    EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null);
    assertThat(properties.cookie().secure()).isTrue();
  }

  @Test
  void hstsDefaultsToUnconditional() {
    EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null);
    assertThat(properties.hsts().unconditional()).isTrue();
  }

  @Test
  void hstsUnconditionalHonoursAnExplicitFalse() {
    assertThat(new EdgePerimeterProperties.Hsts(false).unconditional()).isFalse();
  }

  @Test
  void identityIssuerDefaultsToReferenceIssuer() {
    EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null);
    assertThat(properties.identity().issuerUri())
        .isEqualTo(EdgePerimeterProperties.DEFAULT_ISSUER_URI);
  }

  @Test
  void identityIssuerRejectsBlankExplicitIssuer() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity(" "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not be blank");
  }

  @Test
  void identityIssuerRejectsLeadingOrTrailingWhitespace() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity(" https://idp.acme.example/realms/demo"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not include leading or trailing whitespace");
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example/realms/demo "))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not include leading or trailing whitespace");
  }

  @Test
  void identityIssuerRejectsControlCharacters() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example/realms/demo\u0000"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.identity.issuer-uri must not contain control characters");
  }

  @Test
  void identityIssuerRejectsMalformedIssuer() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("not an issuer"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("absolute HTTP(S) URI");
  }

  @Test
  void identityIssuerRejectsInvalidExplicitPorts() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example:99999"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("valid HTTP(S) port");

    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example:"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("valid HTTP(S) port");
  }

  @Test
  void identityIssuerRejectsRemotePlainHttpIssuer() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("http://idp.acme.example"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must use HTTPS except for loopback");
  }

  @Test
  void identityIssuerAllowsLoopbackPlainHttpForLocalDevelopment() {
    assertThat(new EdgePerimeterProperties.Identity("http://localhost:8081/realms/demo").issuerUri())
        .isEqualTo("http://localhost:8081/realms/demo");
  }

  @Test
  void identityIssuerAllowsIpv6LoopbackPlainHttpForLocalDevelopment() {
    assertThat(new EdgePerimeterProperties.Identity("http://[::1]:8081/realms/demo").issuerUri())
        .isEqualTo("http://[::1]:8081/realms/demo");
  }

  @Test
  void identityIssuerRejectsUserInfoCredentials() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://userinfo@idp.acme.example"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include user-info credentials");
  }

  @Test
  void identityIssuerRejectsQueryAndFragmentComponents() {
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example/issuer?env=dev"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include query or fragment");
    assertThatThrownBy(() -> new EdgePerimeterProperties.Identity("https://idp.acme.example/issuer#fragment"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not include query or fragment");
  }

  @Test
  void serviceJwtAudienceDefaultsToReferenceAudience() {
    EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null);
    assertThat(properties.serviceJwt().audiences())
        .containsExactly(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE);
  }

  @Test
  void serviceJwtAudiencesRejectBlankEntries() {
    assertThatThrownBy(
            () ->
                new EdgePerimeterProperties.ServiceJwt(
                    java.util.List.of(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE, " ")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not contain blank entries");
  }

  @Test
  void serviceJwtAudiencesRejectLeadingOrTrailingWhitespace() {
    assertThatThrownBy(
            () ->
                new EdgePerimeterProperties.ServiceJwt(
                    java.util.List.of(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE + " ")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not include leading or trailing whitespace");
  }

  @Test
  void serviceJwtAudiencesRejectControlCharacters() {
    assertThatThrownBy(
            () ->
                new EdgePerimeterProperties.ServiceJwt(
                    java.util.List.of(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE + "\nforged")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("edge.service-jwt.audiences must not contain control characters");
  }
}
