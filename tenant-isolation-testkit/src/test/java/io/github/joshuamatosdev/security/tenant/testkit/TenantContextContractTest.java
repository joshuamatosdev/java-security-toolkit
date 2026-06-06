package io.github.joshuamatosdev.security.tenant.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import org.junit.jupiter.api.Test;

class TenantContextContractTest implements TenantContextContract {

    @Test
    void contractCleanupClearsContextBeforeRestoringTheDefaultGuard() {
        TenantContext.runAs(TenantIds.ACME, () -> {
            TenantContext.useTenantTransactionActiveCheck(() -> true);

            clearTenantContext();

            assertThat(TenantContext.current()).isEmpty();
        });
    }

    @Test
    void contractCleanupRestoresTheDefaultTransactionGuard() throws Exception {
        try {
            clearTenantContext();
            setSpringTransactionActive(true);

            assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, () -> {}))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("active transaction");
        } finally {
            setSpringTransactionActive(false);
        }
    }

    private static void setSpringTransactionActive(final boolean active) throws Exception {
        Class.forName("org.springframework.transaction.support.TransactionSynchronizationManager")
                .getMethod("setActualTransactionActive", boolean.class)
                .invoke(null, active);
    }
}
