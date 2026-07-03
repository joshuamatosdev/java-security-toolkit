package io.github.joshuamatosdev.security.edge.filter;

import io.github.joshuamatosdev.security.edge.chain.ServiceApiSecurityChainConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.lang.NonNull;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Strips any inbound {@code Authorization} header on the browser plane before any other filter
 * observes it.
 *
 * <p>The two credential planes must never blur. Browsers authenticate to the BFF with a session
 * cookie; a bearer token belongs only on the service plane ({@code /api/service/**}), where the
 * resource server validates it. A browser-supplied {@code Authorization} header on a browser-plane
 * path is therefore anomalous: at best a confused client, at worst a hostile script probing whether
 * it can smuggle a service identity through the session boundary. The header is removed and the
 * event is logged at WARN so the probe leaves a forensic trail rather than passing silently.
 *
 * <p>The service plane is explicitly exempt — that plane's whole contract is to accept bearer
 * tokens, so stripping there would break it. Runs at {@link Ordered#HIGHEST_PRECEDENCE} so the
 * header is gone before the security chains run.
 *
 * <p>Why this exists: browser and service credential planes must not merge through an
 * attacker-supplied Authorization header.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BrowserCredentialIsolationFilter implements WebFilter {

  private static final Logger log = LoggerFactory.getLogger(BrowserCredentialIsolationFilter.class);

  private static final ServerWebExchangeMatcher SERVICE_PLANE_MATCHER =
      ServerWebExchangeMatchers.pathMatchers(ServiceApiSecurityChainConfig.SERVICE_MATCHER);

  @Override
  public @NonNull Mono<Void> filter(
      @NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();
    String logPath = safeLogPath(request);

    // Match the service security chain's /api/service/** matcher exactly, including Spring's path
    // parsing rules for matrix parameters and encoded separators. A hand-written prefix check can
    // diverge from that matcher and strip a credential from a request the service plane owns.
    return SERVICE_PLANE_MATCHER
        .matches(exchange)
        .flatMap(
            match -> {
              if (match.isMatch()) {
                return chain.filter(exchange);
              }
              return filterBrowserPlane(exchange, chain, request, logPath);
            });
  }

  private Mono<Void> filterBrowserPlane(
      ServerWebExchange exchange, WebFilterChain chain, ServerHttpRequest request, String logPath) {
    if (request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
      log.warn(
          "inbound_credential_header_stripped header={} method={} path={} remote={}",
          HttpHeaders.AUTHORIZATION,
          request.getMethod(),
          logPath,
          request.getRemoteAddress() != null ? request.getRemoteAddress().getAddress() : null);
      ServerHttpRequest mutated =
          request.mutate().headers(h -> h.remove(HttpHeaders.AUTHORIZATION)).build();
      return chain.filter(exchange.mutate().request(mutated).build());
    }
    return chain.filter(exchange);
  }

  static String safeLogPath(ServerHttpRequest request) {
    String rawPath = request.getURI().getRawPath();
    return escapeControlCharacters(rawPath == null ? "" : rawPath);
  }

  private static String escapeControlCharacters(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if (Character.isISOControl(character)) {
        escaped.append("\\u");
        String hex = Integer.toHexString(character);
        escaped.append("0".repeat(4 - hex.length())).append(hex);
      } else {
        escaped.append(character);
      }
    }
    return escaped.toString();
  }
}
