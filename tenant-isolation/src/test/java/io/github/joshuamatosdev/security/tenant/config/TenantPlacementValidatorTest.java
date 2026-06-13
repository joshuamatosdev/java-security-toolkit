package io.github.joshuamatosdev.security.tenant.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import org.junit.jupiter.api.Test;

class TenantPlacementValidatorTest {

    @Test
    void defaultDatabasePoolNameUsesTenantId() {
        final TenantIsolationProperties.DatabaseTenantProperties placement =
                new TenantIsolationProperties.DatabaseTenantProperties(
                        TenantIds.ACME.toString(),
                        "jdbc:postgresql://localhost:5432/acme",
                        "tenant_app",
                        "secret",
                        null,
                        null,
                        null,
                        null);

        assertThat(TenantPlacementValidator.databasePoolName(placement))
                .isEqualTo("tenant-db-" + TenantIds.ACME);
    }
}
