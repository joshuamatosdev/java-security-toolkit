package io.github.joshuamatosdev.security.edge.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Proves the cookie-secure default fails safe. The "defaults to true" promise must hold not only
 * when the whole {@code edge.cookie} block is absent, but also when the block is present with
 * {@code secure} omitted — the case a primitive field would silently bind to {@code false}.
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
  void serviceJwtAudienceDefaultsToReferenceAudience() {
    EdgePerimeterProperties properties = new EdgePerimeterProperties(null, null, null);
    assertThat(properties.serviceJwt().audiences())
        .containsExactly(EdgePerimeterProperties.DEFAULT_SERVICE_AUDIENCE);
  }
}
