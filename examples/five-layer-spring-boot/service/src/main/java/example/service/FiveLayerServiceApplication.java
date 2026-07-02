package example.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The resource service half of the composed five-layer example: layers 2 (authorization) and 5
 * (data) in one application, sitting behind the {@code bff} subproject (layers 1 and 4).
 *
 * <p>The application owns exactly five things: the two starter dependencies, the configuration in
 * {@code application.yaml}, {@link TenantBindingFilter}, {@link RequestContexts}, and the database
 * DDL in {@code src/test/resources/db/init.sql}. Everything else — the claim-signing datasource
 * proxy, fail-closed borrows, the authorization decision core, audit, and the 403 denial advice —
 * ships in the starters.
 */
@SpringBootApplication
public class FiveLayerServiceApplication {

    public static void main(final String[] args) {
        SpringApplication.run(FiveLayerServiceApplication.class, args);
    }
}
