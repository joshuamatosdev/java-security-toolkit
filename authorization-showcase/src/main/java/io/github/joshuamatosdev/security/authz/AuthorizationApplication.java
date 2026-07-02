package io.github.joshuamatosdev.security.authz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Boots the authorization showcase around the decision core the starter wires.
 *
 * <p>The component scan is restricted to the showcase's own packages ({@code web}, {@code
 * persistence}); the decision-core beans come from the starter's auto-configuration. Scanning the
 * whole {@code authz} root would also pick up the starter's {@code @Configuration} classes and
 * register them a second time.
 *
 * <p>Why this exists: a runnable Spring boundary keeps the layered authorization pattern
 * executable and easy to test end to end.
 */
@SpringBootApplication(scanBasePackages = {
    "io.github.joshuamatosdev.security.authz.web",
    "io.github.joshuamatosdev.security.authz.persistence"
})
public class AuthorizationApplication {

    public static void main(final String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }
}
