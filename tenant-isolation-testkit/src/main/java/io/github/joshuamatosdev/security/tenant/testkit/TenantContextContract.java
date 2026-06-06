package io.github.joshuamatosdev.security.tenant.testkit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Reusable contract tests for tenant context binding integrations. */
public interface TenantContextContract {

    /** Ordinary tenant used by the contract. */
    default TenantId ordinaryTenant() {
        return TenantIds.ACME;
    }

    @AfterEach
    default void clearTenantContext() {
        TenantContext.useTenantTransactionActiveCheck(() -> false);
        TenantContext.clear();
        TenantContext.resetTenantTransactionActiveCheck();
    }

    @Test
    default void scopedTenantBindingRestoresPriorContext() {
        assertThat(TenantContext.current()).isEmpty();

        TenantContext.runAs(ordinaryTenant(), () -> assertThat(TenantContext.requireCurrent())
                .isEqualTo(ordinaryTenant()));

        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    default void ordinaryBindingRejectsSystemOpsTenant() {
        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.SYSTEM_OPS, () -> { }))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SYSTEM_OPS tenant requires");
    }
}
