package io.github.joshuamatosdev.security.edge.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

/**
 * Cookie Policy Config for the edge module.
 *
 * <p>Why this exists: CORS and cookie policy are credentialed browser trust decisions, so their
 * allow-lists need to be explicit and auditable.
 */
@Configuration
public class CookiePolicyConfig {

  @Bean
  public WebSessionIdResolver webSessionIdResolver(EdgeProperties properties) {
    var resolver = new CookieWebSessionIdResolver();
    resolver.addCookieInitializer(
        cookie -> cookie.secure(properties.cookie().secure()).httpOnly(true).sameSite("Lax"));
    return resolver;
  }
}
