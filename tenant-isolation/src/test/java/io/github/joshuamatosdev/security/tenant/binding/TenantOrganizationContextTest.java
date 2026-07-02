package io.github.joshuamatosdev.security.tenant.binding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Unit tests for the organization dimension of {@link TenantContext}:
 *
 * <ol>
 *   <li>the organization binds and restores atomically with the tenant — there is no entry point
 *       that binds an organization alone;
 *   <li>tenant-only bindings and the system-operations tenant carry no organization;
 *   <li>{@code requireCurrentOrganization} fails closed when the dimension is absent;
 *   <li>the tenant-before-transaction guard also rejects an organization switch (including an
 *       unbind) once a tenant transaction is active.
 * </ol>
 *
 * <p>Why this is important to test: an organization leak or a tenant/organization skew would scope
 * rows to the wrong sub-boundary while the tenant boundary still looks correct.
 */
class TenantOrganizationContextTest {

    private static final String ACTIVE_TRANSACTION_MESSAGE = "active transaction";
    private static final OrganizationId ENGINEERING =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
    private static final OrganizationId LOGISTICS =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e2");

    @AfterEach
    void reset() {
        TransactionSynchronizationManager.setActualTransactionActive(false);
        TenantContext.useTenantTransactionActiveCheck(() -> false);
        TenantContext.clear();
        TenantContext.resetTenantTransactionActiveCheck();
    }

    @Test
    void organizationBindsAndRestoresAtomicallyWithTheTenant() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThat(TenantContext.current()).contains(TenantIds.ACME);
            assertThat(TenantContext.currentOrganization()).contains(ENGINEERING);
        });

        assertThat(TenantContext.current()).isEmpty();
        assertThat(TenantContext.currentOrganization()).isEmpty();
    }

    @Test
    void nestedOrganizationScopeRestoresTheOuterOrganization() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TenantContext.runAs(TenantIds.ACME, LOGISTICS, () ->
                    assertThat(TenantContext.currentOrganization()).contains(LOGISTICS));

            assertThat(TenantContext.currentOrganization()).contains(ENGINEERING);
        });
    }

    @Test
    void tenantOnlyBindingCarriesNoOrganization() {
        TenantContext.runAs(TenantIds.ACME, () ->
                assertThat(TenantContext.currentOrganization()).isEmpty());
    }

    @Test
    void systemOpsBindingCarriesNoOrganization() {
        TenantContext.runAsSystemOps(() ->
                assertThat(TenantContext.currentOrganization()).isEmpty());
    }

    @Test
    void supplyAsWithOrganizationReturnsTheValueAndRestores() {
        final String result = TenantContext.supplyAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThat(TenantContext.currentOrganization()).contains(ENGINEERING);
            return "scoped";
        });

        assertThat(result).isEqualTo("scoped");
        assertThat(TenantContext.currentOrganization()).isEmpty();
    }

    @Test
    void requireCurrentOrganizationFailsClosedWhenAbsent() {
        assertThatThrownBy(TenantContext::requireCurrentOrganization)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("organization");

        TenantContext.runAs(TenantIds.ACME, () ->
                assertThatThrownBy(TenantContext::requireCurrentOrganization)
                        .isInstanceOf(SecurityException.class)
                        .hasMessageContaining("without organization binding"));
    }

    @Test
    void requireCurrentOrganizationReturnsTheBoundOrganization() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () ->
                assertThat(TenantContext.requireCurrentOrganization()).isEqualTo(ENGINEERING));
    }

    @Test
    void organizationOverloadsRejectNullOrganizationBeforeRunningWork() {
        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("organization must not be null");

        assertThatThrownBy(() -> TenantContext.supplyAs(TenantIds.ACME, null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("organization must not be null");
    }

    @Test
    void switchingOrganizationInsideActiveTransactionFailsClosed() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, LOGISTICS, () -> {}))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot switch organization binding")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void unbindingTheOrganizationInsideActiveTransactionFailsClosed() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, () -> {}))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot switch organization binding")
                    .hasMessageContaining("none")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void reenteringTheSameTenantAndOrganizationInsideActiveTransactionIsAllowed() {
        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatCode(() -> TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {}))
                    .doesNotThrowAnyException();

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void restoringAcrossAnOrganizationChangeInsideActiveTransactionFailsClosed() {
        final AtomicBoolean tenantTransactionActive = new AtomicBoolean(false);
        TenantContext.useTenantTransactionActiveCheck(tenantTransactionActive::get);

        TenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, LOGISTICS,
                    () -> tenantTransactionActive.set(true)))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot restore tenant binding")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
            // The failed restore leaves the inner binding in place (fail-closed).
            assertThat(TenantContext.currentOrganization()).contains(LOGISTICS);
            // Release the guard so the outer scope can restore and the test ends clean.
            tenantTransactionActive.set(false);
        });
    }
}
