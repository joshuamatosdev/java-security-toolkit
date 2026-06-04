package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Characterizes the bare-name contract of the service-plane roles converter. The WebTestClient
 * slice tests authenticate with {@code mockJwt().authorities(...)}, which injects authorities
 * directly and bypasses this converter; this test exercises the real converter so the mapping from
 * a {@code roles} claim to {@code ROLE_*} authorities is actually proven.
 */
class ServiceApiRolesConverterTest {

  private static Jwt jwtWithRoles(List<String> roles) {
    return new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(300),
        Map.of("alg", "RS256"),
        Map.of("sub", "service-client", "roles", roles));
  }

  private List<String> authoritiesFor(Jwt jwt) {
    AbstractAuthenticationToken token =
        ServiceApiSecurityChainConfig.reactiveRolesConverter().convert(jwt).block();
    assertThat(token).isNotNull();
    return token.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
  }

  @Test
  void bareRoleNamesGainTheSingleRolePrefix() {
    assertThat(authoritiesFor(jwtWithRoles(List.of("service", "admin"))))
        .containsExactlyInAnyOrder("ROLE_service", "ROLE_admin");
  }

  @Test
  void anAlreadyPrefixedClaimIsDoublePrefixedAndFailsClosed() {
    // Documents the contract: a misconfigured issuer that ships "ROLE_service" is neutered to
    // ROLE_ROLE_service, which does NOT satisfy hasAuthority("ROLE_service") — fails closed.
    assertThat(authoritiesFor(jwtWithRoles(List.of("ROLE_service"))))
        .containsExactly("ROLE_ROLE_service")
        .doesNotContain("ROLE_service");
  }

  @Test
  void aTokenWithoutARolesClaimYieldsNoAuthorities() {
    Jwt jwt =
        new Jwt(
            "token-value",
            Instant.now(),
            Instant.now().plusSeconds(300),
            Map.of("alg", "RS256"),
            Map.of("sub", "service-client"));

    assertThat(authoritiesFor(jwt)).isEmpty();
  }
}
