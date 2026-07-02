package io.github.joshuamatosdev.security.authz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Boots the authorization showcase. Component-scans the {@code authz} package and its web shell.
 *
 * <p>Why this exists: a runnable Spring boundary keeps the layered authorization pattern
 * executable and easy to test end to end.
 */
@SpringBootApplication
public class AuthorizationApplication {

    public static void main(final String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }
}
