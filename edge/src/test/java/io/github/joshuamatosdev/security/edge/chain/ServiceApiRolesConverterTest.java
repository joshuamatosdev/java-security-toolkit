package io.github.joshuamatosdev.security.edge.chain;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Characterizes the bare-name contract of the service-plane roles converter. The WebTestClient
 * slice tests authenticate with {@code mockJwt().authorities(...)}, which injects authorities
 * directly and bypasses this converter; this test exercises the real converter so the mapping from
 * a {@code roles} claim to {@code ROLE_*} authorities is actually proven.
 *
 * <p>Why this is important to test: browser sessions and service JWTs are separate credential
 * planes, and validator drift could accept the wrong token.
 */
class ServiceApiRolesConverterTest {

  private static Jwt jwtWithRoles(Object roles) {
    return new Jwt(
        "token-value",
        Instant.now(),
        Instant.now().plusSeconds(300),
        Map.of("alg", "RS256"),
        Map.of("sub", "service-client", "roles", roles));
  }

  private List<String> authoritiesFor(Jwt jwt) {
    AbstractAuthenticationToken token =
        Objects.requireNonNull(
            ServiceApiSecurityChainConfig.reactiveRolesConverter().convert(jwt).block());
    return token.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .filter(authority -> authority.startsWith("ROLE_"))
        .toList();
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
  void scalarRolesClaimYieldsNoAuthorities() {
    assertThat(authoritiesFor(jwtWithRoles("service"))).isEmpty();
  }

  @Test
  void rolesClaimWithNonStringElementYieldsNoAuthorities() {
    assertThat(authoritiesFor(jwtWithRoles(List.of("service", 7)))).isEmpty();
  }

  @Test
  void rolesClaimWithBlankElementYieldsNoAuthorities() {
    assertThat(authoritiesFor(jwtWithRoles(List.of("service", " ")))).isEmpty();
  }

  @Test
  void rolesClaimWithWhitespacePaddedElementYieldsNoAuthorities() {
    assertThat(authoritiesFor(jwtWithRoles(List.of("service", " admin")))).isEmpty();
  }

  @Test
  void rolesClaimWithControlCharacterElementYieldsNoAuthorities() {
    assertThat(authoritiesFor(jwtWithRoles(List.of("service", "admin\nforged")))).isEmpty();
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
