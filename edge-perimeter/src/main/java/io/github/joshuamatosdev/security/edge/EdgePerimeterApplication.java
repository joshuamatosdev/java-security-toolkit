package io.github.joshuamatosdev.security.edge;

import io.github.joshuamatosdev.security.edge.config.EdgePerimeterProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Edge perimeter showcase: a backend-for-frontend (BFF) security boundary with two explicit
 * credential planes.
 *
 * <ul>
 *   <li><b>Browser plane</b> — session cookie minted by OIDC Authorization-Code + PKCE login,
 *       CSRF double-submit cookie, deny-by-default route map, security headers, actuator
 *       lockdown. See {@code chain.BrowserSecurityChainConfig}.
 *   <li><b>Service plane</b> ({@code /api/service/**}) — stateless OAuth2 resource server
 *       validating bearer JWTs. See {@code chain.ServiceApiSecurityChainConfig}.
 * </ul>
 *
 * <p>The two planes never blur: a bearer token presented on the browser plane is stripped and
 * flagged ({@code filter.BrowserCredentialIsolationFilter}), and the service plane carries no
 * session, no CSRF, and no CORS surface.
 */
@SpringBootApplication
@EnableConfigurationProperties(EdgePerimeterProperties.class)
public class EdgePerimeterApplication {

  public static void main(String[] args) {
    SpringApplication.run(EdgePerimeterApplication.class, args);
  }
}
