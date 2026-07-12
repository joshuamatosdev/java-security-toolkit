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

    /** Context instance supplied by the adopter. */
    TenantContext tenantContext();

    @AfterEach
    default void clearTenantContext() {
        tenantContext().clear();
    }

    @Test
    default void scopedTenantBindingRestoresPriorContext() {
        assertThat(tenantContext().current()).isEmpty();

        tenantContext().runAs(ordinaryTenant(), () -> assertThat(tenantContext().requireCurrent())
                .isEqualTo(ordinaryTenant()));

        assertThat(tenantContext().current()).isEmpty();
    }

    @Test
    default void ordinaryBindingRejectsSystemOpsTenant() {
        assertThatThrownBy(() -> tenantContext().runAs(TenantIds.SYSTEM_OPS, () -> { }))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("SYSTEM_OPS tenant requires");
    }
}
