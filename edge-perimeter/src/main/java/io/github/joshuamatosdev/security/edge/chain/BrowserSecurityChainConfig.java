package io.github.joshuamatosdev.security.edge.chain;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import io.github.joshuamatosdev.security.edge.headers.SecurityHeadersFilter;
import java.util.function.Function;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.WebFilter;

/**
 * Browser plane: the BFF security boundary for everything not owned by the service chain.
 *
 * <p>Registered at {@link Order}(2) so the service chain (order 1, matching {@code
 * /api/service/**}) wins on its paths and every other request falls through to here. The shape:
 *
 * <ul>
 *   <li><b>Deny-by-default</b> — the route map ends in {@code anyExchange().authenticated()} and
 *       there is no permit-all fallthrough. The actuator is locked the same way: health and info
 *       are explicitly permitted, then {@code /actuator/**} is explicitly denied, so an endpoint
 *       accidentally exposed in {@code management.endpoints.web.exposure} is still unreachable.
 *   <li><b>Narrow-before-broad</b> — the audit-export exception is registered before the broad
 *       admin gate so an auditor reaches it (first-match-wins). See {@link RouteAuthorities}.
 *   <li><b>OIDC login</b> via Authorization-Code + PKCE; the generated login page is suppressed so
 *       the gateway leaks no client-registration identity (the SPA owns all login UX).
 *   <li><b>CSRF</b> double-submit cookie, <b>CORS</b> credentialed allow-list, <b>security
 *       headers</b> on every response.
 * </ul>
 */
@Configuration
@EnableWebFluxSecurity
public class BrowserSecurityChainConfig {

  @Bean
  @Order(2)
  public SecurityWebFilterChain browserSecurityFilterChain(
      ServerHttpSecurity http,
      ServerCsrfTokenRepository csrfTokenRepository,
      ServerCsrfTokenRequestHandler csrfTokenRequestHandler,
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
      CorsConfigurationSource corsConfigurationSource) {
    return http.cors(cors -> cors.configurationSource(corsConfigurationSource))
        .csrf(
            csrf ->
                csrf.csrfTokenRepository(csrfTokenRepository)
                    .csrfTokenRequestHandler(csrfTokenRequestHandler))
        .authorizeExchange(
            exchanges ->
                exchanges
                    .pathMatchers(RouteAuthorities.PUBLIC_PATHS)
                    .permitAll()
                    .pathMatchers("/actuator/health/**", "/actuator/info")
                    .permitAll()
                    .pathMatchers("/actuator/**")
                    .denyAll()
                    // Narrow exception MUST precede the broad admin gate (first-match-wins).
                    .pathMatchers(RouteAuthorities.AUDIT_EXPORT_PATHS)
                    .hasAnyAuthority(RouteAuthorities.AUDIT_EXPORT_AUTHORITIES)
                    .pathMatchers(RouteAuthorities.ADMIN_PATHS)
                    .hasAnyAuthority(RouteAuthorities.ADMIN_AUTHORITIES)
                    .anyExchange()
                    .authenticated())
        // An explicit loginPage suppresses Spring Security's generated OAuth2 login page, which
        // would otherwise leak the client-registration id and confirm the IdP backend. Pointing
        // it at the single client's authorization endpoint makes an HTML auth challenge redirect
        // straight into the OIDC round-trip. The SPA owns all login UX.
        .oauth2Login(
            oauth2 ->
                oauth2
                    .loginPage("/oauth2/authorization/idp")
                    .authorizationRequestResolver(authorizationRequestResolver))
        .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .build();
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public WebFilter securityHeadersFilter(EdgePerimeterProperties properties) {
    return new SecurityHeadersFilter(properties.hsts().unconditional());
  }

  /**
   * Pins the OIDC ID-token JWS algorithm to {@code RS256} for every client registration.
   *
   * <p>A drift guard: Spring Security's default resolver reads {@code id_token_signed_response_alg}
   * from the provider metadata. If a future IdP rebuild advertised a weaker algorithm, or a client
   * registration were mis-built, the decoder here still accepts only RS256 rather than silently
   * consuming an algorithm the BFF never approved. Extracted to a named static reference so it is
   * unit-testable (the factory exposes no getter for its resolver).
   */
  static final Function<ClientRegistration, JwsAlgorithm> ID_TOKEN_RS256_RESOLVER =
      registration -> SignatureAlgorithm.RS256;

  @Bean
  public ReactiveJwtDecoderFactory<ClientRegistration> oidcIdTokenDecoderFactory(
      EdgePerimeterProperties properties) {
    var factory = new ReactiveOidcIdTokenDecoderFactory();
    factory.setJwsAlgorithmResolver(ID_TOKEN_RS256_RESOLVER);
    factory.setJwtValidatorFactory(oidcIdTokenValidatorFactory(properties.identity().issuerUri()));
    return factory;
  }

  static Function<ClientRegistration, OAuth2TokenValidator<Jwt>> oidcIdTokenValidatorFactory(
      String issuerUri) {
    return registration ->
        new DelegatingOAuth2TokenValidator<>(
            new OidcIdTokenValidator(registration), new JwtIssuerValidator(issuerUri));
  }
}
