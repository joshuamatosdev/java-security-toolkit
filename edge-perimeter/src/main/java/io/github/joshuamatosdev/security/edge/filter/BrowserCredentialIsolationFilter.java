package io.github.joshuamatosdev.security.edge.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
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
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BrowserCredentialIsolationFilter implements WebFilter {

  private static final Logger log = LoggerFactory.getLogger(BrowserCredentialIsolationFilter.class);

  /** Base path of the service plane (no trailing slash). */
  public static final String SERVICE_PLANE_BASE = "/api/service";

  /** Path prefix of the service plane, whose contract legitimately accepts bearer tokens. */
  public static final String SERVICE_PLANE_PREFIX = SERVICE_PLANE_BASE + "/";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();
    String path = request.getURI().getPath();

    // Match the service security chain's /api/service/** matcher exactly, which owns the bare
    // /api/service base as well as everything under it. If this predicate were narrower, the filter
    // would strip the credential of a request the service plane then tries to authenticate.
    if (path.equals(SERVICE_PLANE_BASE) || path.startsWith(SERVICE_PLANE_PREFIX)) {
      return chain.filter(exchange);
    }

    if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
      log.warn(
          "inbound_credential_header_stripped header={} method={} path={} remote={}",
          HttpHeaders.AUTHORIZATION,
          request.getMethod(),
          path,
          request.getRemoteAddress() != null ? request.getRemoteAddress().getAddress() : null);
      ServerHttpRequest mutated =
          request.mutate().headers(h -> h.remove(HttpHeaders.AUTHORIZATION)).build();
      return chain.filter(exchange.mutate().request(mutated).build());
    }
    return chain.filter(exchange);
  }
}
