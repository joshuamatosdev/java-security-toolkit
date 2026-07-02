package example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Consumer application for the tenant-isolation walkthrough.
 *
 * <p>The application owns exactly four things: the starter dependency, the configuration in
 * {@code application.yaml}, {@link TenantBindingFilter}, and the database DDL in
 * {@code src/test/resources/db/init.sql}. Everything else — the claim-signing datasource proxy,
 * pool routing, fail-closed borrow behavior — ships in the starter.
 */
@SpringBootApplication
public class TenantIsolationExampleApplication {

    public static void main(final String[] args) {
        SpringApplication.run(TenantIsolationExampleApplication.class, args);
    }
}
