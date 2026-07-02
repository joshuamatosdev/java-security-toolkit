package io.github.joshuamatosdev.security.edge.csrf;

import io.github.joshuamatosdev.security.edge.config.EdgeProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestHandler;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

/**
 * CSRF wiring for the browser plane: a cookie-backed token repository plus the SPA-compatible
 * request handler, shared as beans so {@code BrowserSecurityChainConfig} and any logout handler
 * use the same instances (the clear-cookie attributes must match the cookie the browser holds).
 *
 * <p>Why this exists: CSRF wiring keeps the SPA request flow compatible with Spring token masking
 * while preserving same-site request protection.
 */
@Configuration
public class CsrfProtectionConfig {

  /**
   * Cookie-backed CSRF token repository for the SPA double-submit pattern.
   *
   * <p>{@code withHttpOnlyFalse()} is a deliberate tradeoff: the SPA's JavaScript must read the
   * {@code XSRF-TOKEN} cookie to echo it back as the {@code X-XSRF-TOKEN} header, so the cookie
   * cannot be HttpOnly. The exposure — a same-origin XSS could read the token and forge requests —
   * is covered by a layered defense, each layer a different attack class:
   *
   * <ol>
   *   <li><b>Strict CSP</b> (in {@code SecurityHeadersFilter}: {@code script-src 'self'}, no
   *       {@code 'unsafe-inline'}) blocks the common injected-script XSS vectors — inline and
   *       remote-origin scripts — sharply shrinking the same-origin read-and-forge surface. It is
   *       not absolute: a DOM-based gadget in an already-allowed same-origin script can still run, so
   *       this layer reduces rather than eliminates that surface.
   *   <li><b>SameSite=Lax</b> on this cookie blocks third-party-context CSRF.
   *   <li>The perimeter's deny-by-default route map plus plane separation keep the blast radius of
   *       any forged request inside the authenticated browser surface.
   * </ol>
   */
  @Bean
  public ServerCsrfTokenRepository csrfTokenRepository(EdgeProperties properties) {
    var repository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
    repository.setCookiePath("/");
    repository.setCookieCustomizer(
        cookie -> cookie.secure(properties.cookie().secure()).sameSite("Lax"));
    return repository;
  }

  @Bean
  public ServerCsrfTokenRequestHandler csrfTokenRequestHandler() {
    return new SpaCompatibleXorServerCsrfTokenRequestHandler();
  }

  /**
   * Forces the deferred {@link CsrfToken} to materialize so the {@code Set-Cookie: XSRF-TOKEN}
   * header is written even on responses that never touch the token attribute (e.g. a safe GET).
   * Without this the SPA's very first request would receive no token to echo on its first mutation.
   */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public WebFilter csrfCookieMaterializingFilter() {
    return (exchange, chain) -> {
      exchange
          .getResponse()
          .beforeCommit(
              () -> {
                Mono<CsrfToken> token = exchange.getAttribute(CsrfToken.class.getName());
                return token == null ? Mono.empty() : token.then();
              });
      return chain.filter(exchange);
    };
  }
}
