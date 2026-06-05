package io.github.joshuamatosdev.security.tenant;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point for the tenant-isolation reference module.
 *
 * <p>The application intentionally has little behavior at this layer: the module exists to
 * demonstrate datasource wiring and database-enforced tenant isolation, so runtime security
 * behavior lives in the datasource, binding, and schema components.
 *
 * <p>Why this exists: a runnable Spring boundary keeps the tenant-isolation pattern executable,
 * configurable, and testable instead of only described in ADR prose.
 */
@SpringBootApplication
public class TenantIsolationApplication {

    /**
     * Creates the Spring configuration class instance.
     *
     * <p>Spring Boot instantiates this class as part of component scanning, so the constructor stays
     * public and side-effect free.
     */
    public TenantIsolationApplication() {}

    /**
     * Starts the Spring Boot application context.
     *
     * @param args command-line arguments forwarded to Spring Boot
     */
    public static void main(final String[] args) {
        SpringApplication.run(TenantIsolationApplication.class, args);
    }
}
