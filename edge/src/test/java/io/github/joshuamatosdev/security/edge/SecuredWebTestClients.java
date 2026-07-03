package io.github.joshuamatosdev.security.edge;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import org.springframework.context.ApplicationContext;
import org.springframework.test.web.reactive.server.WebTestClient;

public final class SecuredWebTestClients {

  private SecuredWebTestClients() {}

  public static WebTestClient bindTo(ApplicationContext context) {
    return WebTestClient.bindToApplicationContext(context)
        .apply(springSecurity())
        .configureClient()
        .build();
  }
}
