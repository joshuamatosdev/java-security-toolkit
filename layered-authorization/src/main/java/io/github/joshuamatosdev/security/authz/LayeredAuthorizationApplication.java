package io.github.joshuamatosdev.security.authz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Boots the layered-authorization showcase. Component-scans the {@code authz} package and its web shell.
 */
@SpringBootApplication
public class LayeredAuthorizationApplication {

    public static void main(final String[] args) {
        SpringApplication.run(LayeredAuthorizationApplication.class, args);
    }
}
