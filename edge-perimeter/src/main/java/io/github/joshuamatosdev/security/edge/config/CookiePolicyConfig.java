package io.github.joshuamatosdev.security.edge.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

/** Applies the same browser-cookie transport policy to the reactive session cookie. */
@Configuration
public class CookiePolicyConfig {

  @Bean
  public WebSessionIdResolver webSessionIdResolver(EdgePerimeterProperties properties) {
    var resolver = new CookieWebSessionIdResolver();
    resolver.addCookieInitializer(
        cookie -> cookie.secure(properties.cookie().secure()).httpOnly(true).sameSite("Lax"));
    return resolver;
  }
}
