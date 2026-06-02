package io.github.joshuamatosdev.security.tenant;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TenantIsolationApplication {
    public static void main(final String[] args) {
        SpringApplication.run(TenantIsolationApplication.class, args);
    }
}
