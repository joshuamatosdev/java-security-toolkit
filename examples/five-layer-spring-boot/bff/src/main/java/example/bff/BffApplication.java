package example.bff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The perimeter half of the composed five-layer example: layers 1 (identity) and 4 (transport /
 * runtime) in front of the {@code service} subproject (layers 2 and 5).
 *
 * <p>The application owns exactly three things: the starter dependency, the configuration in
 * {@code application.yaml}, and {@link DocumentRelayController}. The dual security chains, PKCE
 * login, CORS/CSRF/cookie/header hardening, and credential-plane isolation all ship in the edge
 * starter.
 */
@SpringBootApplication
public class BffApplication {

    public static void main(final String[] args) {
        SpringApplication.run(BffApplication.class, args);
    }
}
