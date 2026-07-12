package io.github.joshuamatosdev.security.edge.chain;

import java.util.List;
import java.util.Objects;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.web.server.ServerHttpSecurity;

/**
 * Immutable, ordered browser-route policy shared by authorization and CORS configuration.
 *
 * <p>Rules are evaluated first-match-wins. A narrow route therefore appears before any broader
 * route that contains it. Applications can replace the default bean with another table, matcher,
 * or authorization strategy without changing the security-chain algorithm.
 */
public final class BrowserRouteTable {

  private static final List<HttpMethod> GET_ONLY = List.of(HttpMethod.GET);
  private static final BrowserRouteTable DEFAULTS =
      new BrowserRouteTable(
          List.of(
              route(
                  new MethodPaths(HttpMethod.GET, List.of("/api/public/**")),
                  StandardAuthorization.PERMIT_ALL,
                  GET_ONLY),
              route(
                  new MethodPaths(
                      HttpMethod.GET, List.of("/actuator/health/**", "/actuator/info")),
                  StandardAuthorization.PERMIT_ALL,
                  GET_ONLY),
              route(
                  new AnyMethodPaths(List.of("/actuator/**")),
                  StandardAuthorization.DENY_ALL,
                  GET_ONLY),
              route(
                  new AnyMethodPaths(List.of("/api/documents", "/api/documents/**")),
                  StandardAuthorization.AUTHENTICATED,
                  List.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE)),
              route(
                  new AnyMethodPaths(List.of("/api/admin/audit-export")),
                  new AnyAuthority(List.of("ROLE_auditor", "ROLE_admin")),
                  GET_ONLY),
              route(
                  new AnyMethodPaths(List.of("/api/admin/**")),
                  new AnyAuthority(List.of("ROLE_admin")),
                  GET_ONLY)));

  private final List<BrowserRoute> rules;

  /** Creates a table from rules in first-match-wins order. */
  public BrowserRouteTable(final List<BrowserRoute> rules) {
    Objects.requireNonNull(rules, "rules must not be null");
    if (rules.isEmpty() || rules.stream().anyMatch(Objects::isNull)) {
      throw new IllegalArgumentException("rules must contain non-null route rules");
    }
    this.rules = List.copyOf(rules);
  }

  /** Returns the shipped deny-by-default browser route policy. */
  public static BrowserRouteTable defaults() {
    return DEFAULTS;
  }

  /** Returns the immutable rules in evaluation order. */
  public List<BrowserRoute> rules() {
    return rules;
  }

  private static BrowserRoute route(
      final RouteMatcher matcher,
      final RouteAuthorization authorization,
      final List<HttpMethod> corsMethods) {
    return new BrowserRoute(matcher, authorization, corsMethods);
  }

  /** One ordered authorization rule and its matching browser CORS surface. */
  public record BrowserRoute(
      RouteMatcher matcher,
      RouteAuthorization authorization,
      List<HttpMethod> corsMethods) {

    public BrowserRoute {
      Objects.requireNonNull(matcher, "matcher must not be null");
      Objects.requireNonNull(authorization, "authorization must not be null");
      Objects.requireNonNull(corsMethods, "corsMethods must not be null");
      if (corsMethods.stream().anyMatch(Objects::isNull)) {
        throw new IllegalArgumentException("corsMethods must not contain null");
      }
      corsMethods = List.copyOf(corsMethods);
    }
  }

  /** Pluggable route matcher that also exposes paths for CORS registration. */
  public interface RouteMatcher {
    List<String> paths();

    ServerHttpSecurity.AuthorizeExchangeSpec.Access match(
        ServerHttpSecurity.AuthorizeExchangeSpec exchanges);
  }

  /** Matches paths for every HTTP method. */
  public record AnyMethodPaths(List<String> paths) implements RouteMatcher {

    public AnyMethodPaths {
      paths = requirePaths(paths);
    }

    @Override
    public ServerHttpSecurity.AuthorizeExchangeSpec.Access match(
        final ServerHttpSecurity.AuthorizeExchangeSpec exchanges) {
      return exchanges.pathMatchers(paths.toArray(String[]::new));
    }
  }

  /** Matches paths for one HTTP method. */
  public record MethodPaths(HttpMethod method, List<String> paths) implements RouteMatcher {

    public MethodPaths {
      Objects.requireNonNull(method, "method must not be null");
      paths = requirePaths(paths);
    }

    @Override
    public ServerHttpSecurity.AuthorizeExchangeSpec.Access match(
        final ServerHttpSecurity.AuthorizeExchangeSpec exchanges) {
      return exchanges.pathMatchers(method, paths.toArray(String[]::new));
    }
  }

  /** Strategy that applies one authorization decision to a matched route. */
  @FunctionalInterface
  public interface RouteAuthorization {
    void apply(ServerHttpSecurity.AuthorizeExchangeSpec.Access access);
  }

  /** Standard route decisions that do not carry extra data. */
  public enum StandardAuthorization implements RouteAuthorization {
    PERMIT_ALL {
      @Override
      public void apply(final ServerHttpSecurity.AuthorizeExchangeSpec.Access access) {
        access.permitAll();
      }
    },
    AUTHENTICATED {
      @Override
      public void apply(final ServerHttpSecurity.AuthorizeExchangeSpec.Access access) {
        access.authenticated();
      }
    },
    DENY_ALL {
      @Override
      public void apply(final ServerHttpSecurity.AuthorizeExchangeSpec.Access access) {
        access.denyAll();
      }
    }
  }

  /** Requires at least one authority from an immutable allow-list. */
  public record AnyAuthority(List<String> authorities) implements RouteAuthorization {

    public AnyAuthority {
      Objects.requireNonNull(authorities, "authorities must not be null");
      if (authorities.isEmpty()
          || authorities.stream().anyMatch(value -> value == null || value.isBlank())) {
        throw new IllegalArgumentException("authorities must contain non-blank values");
      }
      authorities = List.copyOf(authorities);
    }

    @Override
    public void apply(final ServerHttpSecurity.AuthorizeExchangeSpec.Access access) {
      access.hasAnyAuthority(authorities.toArray(String[]::new));
    }
  }

  private static List<String> requirePaths(final List<String> paths) {
    Objects.requireNonNull(paths, "paths must not be null");
    if (paths.isEmpty() || paths.stream().anyMatch(value -> value == null || value.isBlank())) {
      throw new IllegalArgumentException("paths must contain non-blank values");
    }
    return List.copyOf(paths);
  }
}
