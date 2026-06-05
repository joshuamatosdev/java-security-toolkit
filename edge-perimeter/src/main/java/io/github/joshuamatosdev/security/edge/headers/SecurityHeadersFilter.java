package io.github.joshuamatosdev.security.edge.headers;

import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Adds OWASP-aligned security response headers to <em>every</em> response the perimeter serves,
 * including responses generated locally by Spring Security (login redirects, 403s) and by the
 * actuator — not just proxied responses.
 *
 * <p>Implemented as a {@link WebFilter} at {@link Ordered#HIGHEST_PRECEDENCE} so the {@code
 * beforeCommit} hook is registered before any other filter writes the response. Headers are set in
 * {@code beforeCommit} rather than eagerly so they survive a response that Spring Security replaces
 * (e.g. an authentication redirect committed by a downstream filter).
 *
 * <p>HSTS emission is the one conditional header. {@code unconditionalHsts} is wired from {@code
 * edge.hsts.unconditional}: true where TLS terminates at an upstream proxy and a stripped {@code
 * X-Forwarded-Proto} must not silently suppress transport pinning; false for plain-HTTP local runs
 * that cannot serve the HTTPS the header would pin browsers to.
 *
 * <p>Why this exists: browser hardening headers are centralized so every response receives the
 * same perimeter baseline.
 */
public class SecurityHeadersFilter implements WebFilter, Ordered {

  private final boolean unconditionalHsts;

  public SecurityHeadersFilter(boolean unconditionalHsts) {
    this.unconditionalHsts = unconditionalHsts;
  }

  public static final String X_CONTENT_TYPE_OPTIONS_HEADER = "X-Content-Type-Options";
  public static final String X_CONTENT_TYPE_OPTIONS_VALUE = "nosniff";

  public static final String X_FRAME_OPTIONS_HEADER = "X-Frame-Options";
  public static final String X_FRAME_OPTIONS_VALUE = "DENY";

  public static final String REFERRER_POLICY_HEADER = "Referrer-Policy";
  public static final String REFERRER_POLICY_VALUE = "strict-origin-when-cross-origin";

  // Explicitly disable the legacy XSS auditor. A value of "0" is correct on modern browsers:
  // the heuristic filter it would otherwise enable has itself been a source of information-leak
  // vulnerabilities, and CSP is the real defense.
  public static final String X_XSS_PROTECTION_HEADER = "X-XSS-Protection";
  public static final String X_XSS_PROTECTION_VALUE = "0";

  public static final String PERMISSIONS_POLICY_HEADER = "Permissions-Policy";
  public static final String PERMISSIONS_POLICY_VALUE =
      "camera=(), microphone=(), geolocation=(), payment=()";

  public static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
  // script-src is set explicitly (not left to the default-src fallback) for clarity, and form-action
  // is added because it has no default-src fallback — without it a form could POST to any origin.
  public static final String CONTENT_SECURITY_POLICY_VALUE =
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
          + "form-action 'self'; frame-ancestors 'none'";

  // Browsing-context and resource isolation: COOP severs cross-origin window.opener references and
  // puts this origin in its own browsing-context group; CORP blocks other origins from embedding this
  // perimeter's responses as no-cors sub-resources.
  public static final String CROSS_ORIGIN_OPENER_POLICY_HEADER = "Cross-Origin-Opener-Policy";
  public static final String CROSS_ORIGIN_OPENER_POLICY_VALUE = "same-origin";

  public static final String CROSS_ORIGIN_RESOURCE_POLICY_HEADER = "Cross-Origin-Resource-Policy";
  public static final String CROSS_ORIGIN_RESOURCE_POLICY_VALUE = "same-origin";

  public static final String STRICT_TRANSPORT_SECURITY_HEADER = "Strict-Transport-Security";
  public static final String STRICT_TRANSPORT_SECURITY_VALUE =
      "max-age=63072000; includeSubDomains; preload";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    exchange
        .getResponse()
        .beforeCommit(
            () -> {
              HttpHeaders headers = exchange.getResponse().getHeaders();
              headers.set(X_CONTENT_TYPE_OPTIONS_HEADER, X_CONTENT_TYPE_OPTIONS_VALUE);
              headers.set(X_FRAME_OPTIONS_HEADER, X_FRAME_OPTIONS_VALUE);
              headers.set(REFERRER_POLICY_HEADER, REFERRER_POLICY_VALUE);
              headers.set(X_XSS_PROTECTION_HEADER, X_XSS_PROTECTION_VALUE);
              headers.set(PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY_VALUE);
              headers.set(CONTENT_SECURITY_POLICY_HEADER, CONTENT_SECURITY_POLICY_VALUE);
              headers.set(CROSS_ORIGIN_OPENER_POLICY_HEADER, CROSS_ORIGIN_OPENER_POLICY_VALUE);
              headers.set(CROSS_ORIGIN_RESOURCE_POLICY_HEADER, CROSS_ORIGIN_RESOURCE_POLICY_VALUE);
              if (unconditionalHsts || isHttps(exchange)) {
                headers.set(STRICT_TRANSPORT_SECURITY_HEADER, STRICT_TRANSPORT_SECURITY_VALUE);
              }
              return Mono.empty();
            });
    return chain.filter(exchange);
  }

  private boolean isHttps(ServerWebExchange exchange) {
    boolean requestSchemeHttps = "https".equalsIgnoreCase(exchange.getRequest().getURI().getScheme());
    String forwardedProto = exchange.getRequest().getHeaders().getFirst("X-Forwarded-Proto");
    if (forwardedProto != null) {
      // A comma-joined chain (proxy1, proxy2) lists the client-facing proto first.
      String firstProto = forwardedProto.split(",", 2)[0].trim();
      return requestSchemeHttps || "https".equalsIgnoreCase(firstProto);
    }
    return requestSchemeHttps;
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }
}
