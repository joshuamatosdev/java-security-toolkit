package io.github.joshuamatosdev.security.edge.chain;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

/**
 * Final perimeter chain that denies requests not owned by an activated credential plane.
 *
 * <p>The service chain owns {@code /api/service/**} at order 1 and the browser chain owns every
 * remaining route at order 2 when OIDC client infrastructure is present. This lowest-precedence
 * chain is the fail-closed floor for partial configurations: a service-only application must not
 * let non-service routes bypass Spring Security merely because the browser chain could not
 * activate. Application-defined chains with an explicit order remain able to own additional
 * routes ahead of this fallback.
 *
 * <p>No authentication mechanism, session, request cache, CORS, or CSRF surface is needed because
 * this chain never authorizes a request.
 */
@Configuration
@EnableWebFluxSecurity
public class FallbackDenySecurityChainConfig {

  @Bean
  @Order(Ordered.LOWEST_PRECEDENCE)
  public SecurityWebFilterChain fallbackDenySecurityFilterChain(ServerHttpSecurity http) {
    return http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .authorizeExchange(exchanges -> exchanges.anyExchange().denyAll())
        .cors(ServerHttpSecurity.CorsSpec::disable)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .logout(ServerHttpSecurity.LogoutSpec::disable)
        .build();
  }
}
