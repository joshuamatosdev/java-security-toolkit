package io.github.joshuamatosdev.security.edge.chain;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import java.util.Collection;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

/**
 * Service plane: a stateless OAuth2 resource server for machine-to-machine calls under {@code
 * /api/service/**}.
 *
 * <p>This chain is registered at {@link Order}(1) with a {@code securityMatcher} so it owns only the
 * service-plane paths; everything else falls through to the browser chain (order 2). The two planes
 * are structurally different credentials: no session, no CSRF (there is no cookie to ride and no
 * browser to forge from — every request must carry a fresh signed bearer token), no CORS surface.
 * Service routes are allow-listed explicitly; an unmatched service path is denied rather than
 * falling through to routing.
 *
 * <p>A missing or invalid token yields {@code 401} with a {@code WWW-Authenticate: Bearer}
 * challenge (resource-server default); a valid token lacking the required role yields {@code 403}.
 * That 401-vs-403 split is the authn-vs-authz boundary made observable.
 *
 * <p>Why this exists: separate security chains encode browser-session and service-token
 * authentication so one credential model cannot authorize the other.
 */
@Configuration
public class ServiceApiSecurityChainConfig {

  /** Path prefix this chain owns. */
  public static final String SERVICE_MATCHER = "/api/service/**";
  private static final String ROLES_CLAIM = "roles";
  private static final String ROLE_AUTHORITY_PREFIX = "ROLE_";

  @Bean
  @Order(1)
  public SecurityWebFilterChain serviceApiSecurityFilterChain(ServerHttpSecurity http) {
    return http.securityMatcher(
            org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
                .pathMatchers(SERVICE_MATCHER))
        .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .authorizeExchange(
            exchanges ->
                exchanges
                    .pathMatchers("/api/service/reports/**")
                    .access(jwtWithAuthority("ROLE_service"))
                    .anyExchange()
                    .denyAll())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(reactiveRolesConverter())))
        // No session, no CSRF, no form/basic login: a bearer token is the only credential.
        // CORS is disabled explicitly, not just left unconfigured: ServerHttpSecurity auto-enables
        // CORS whenever a CorsConfigurationSource bean exists in the context, which would otherwise
        // give this stateless service plane a browser-facing preflight surface it must not have.
        .cors(ServerHttpSecurity.CorsSpec::disable)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .build();
  }

  @Bean
  public OAuth2TokenValidator<Jwt> serviceJwtBoundaryValidator(
      EdgePerimeterProperties properties) {
    return serviceJwtBoundaryValidator(
        properties.identity().issuerUri(), properties.serviceJwt().audiences());
  }

  static OAuth2TokenValidator<Jwt> serviceJwtBoundaryValidator(
      String issuerUri, List<String> audiences) {
    return new DelegatingOAuth2TokenValidator<>(
        new JwtIssuerValidator(issuerUri),
        new JwtClaimValidator<>(
            JwtClaimNames.AUD, aud -> hasAcceptedAudience(aud, audiences)));
  }

  static ReactiveAuthorizationManager<AuthorizationContext> jwtWithAuthority(String authority) {
    return (authentication, context) ->
        authentication
            .map(auth -> new AuthorizationDecision(hasJwtAuthority(auth, authority)))
            .defaultIfEmpty(new AuthorizationDecision(false));
  }

  private static boolean hasJwtAuthority(Authentication authentication, String authority) {
    return authentication instanceof JwtAuthenticationToken
        && authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .anyMatch(authority::equals);
  }

  private static boolean hasAcceptedAudience(Object aud, List<String> audiences) {
    if (aud instanceof String audience) {
      if (hasInvalidClaimText(audience)) {
        return false;
      }
      return audiences.contains(audience);
    }
    if (aud instanceof Collection<?> audienceValues) {
      if (audienceValues.stream().anyMatch(audience -> !(audience instanceof String))) {
        return false;
      }
      if (audienceValues.stream()
          .map(String.class::cast)
          .anyMatch(ServiceApiSecurityChainConfig::hasInvalidClaimText)) {
        return false;
      }
      return audienceValues.stream()
          .map(String.class::cast)
          .anyMatch(audiences::contains);
    }
    return false;
  }

  /**
   * Maps the JWT {@code roles} claim to {@code ROLE_*} authorities, so the service route can require
   * both a JWT-backed authentication and the expected service authority.
   *
   * <p>Contract: the {@code roles} claim carries <b>bare</b> role names ({@code "service"},
   * {@code "admin"}) — this converter adds the single {@code ROLE_} prefix. A claim that ships
   * already-prefixed values ({@code "ROLE_service"}) would be double-prefixed to
   * {@code ROLE_ROLE_service} and fail authorization. That direction fails closed (a token is
   * neutered, never escalated); the prefix is deliberately not stripped here, because silently
   * accepting both shapes would mask an issuer minting the wrong claim format.
   */
  static Converter<Jwt, Mono<AbstractAuthenticationToken>> reactiveRolesConverter() {
    var jwtConverter = new JwtAuthenticationConverter();
    jwtConverter.setJwtGrantedAuthoritiesConverter(
        ServiceApiSecurityChainConfig::serviceRoleAuthorities);
    return new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);
  }

  private static Collection<GrantedAuthority> serviceRoleAuthorities(Jwt jwt) {
    Object rawRoles = jwt.getClaim(ROLES_CLAIM);
    if (!(rawRoles instanceof Collection<?> roles)) {
      return List.of();
    }
    if (roles.stream().anyMatch(role -> !(role instanceof String))) {
      return List.of();
    }
    if (roles.stream()
        .map(String.class::cast)
        .anyMatch(ServiceApiSecurityChainConfig::hasInvalidClaimText)) {
      return List.of();
    }
    return roles.stream()
        .map(String.class::cast)
        .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(ROLE_AUTHORITY_PREFIX + role))
        .toList();
  }

  private static boolean hasInvalidClaimText(String value) {
    return value.isBlank()
        || !value.equals(value.strip())
        || value.chars().anyMatch(Character::isISOControl);
  }
}
