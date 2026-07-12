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
    private TenantContext tenantContext = new TenantContext();

    @AfterEach
    void reset() {
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    @Test
    void organizationBindsAndRestoresAtomicallyWithTheTenant() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThat(tenantContext.current()).contains(TenantIds.ACME);
            assertThat(tenantContext.currentOrganization()).contains(ENGINEERING);
        });

        assertThat(tenantContext.current()).isEmpty();
        assertThat(tenantContext.currentOrganization()).isEmpty();
    }

    @Test
    void nestedOrganizationScopeRestoresTheOuterOrganization() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            tenantContext.runAs(TenantIds.ACME, LOGISTICS, () ->
                    assertThat(tenantContext.currentOrganization()).contains(LOGISTICS));

            assertThat(tenantContext.currentOrganization()).contains(ENGINEERING);
        });
    }

    @Test
    void tenantOnlyBindingCarriesNoOrganization() {
        tenantContext.runAs(TenantIds.ACME, () ->
                assertThat(tenantContext.currentOrganization()).isEmpty());
    }

    @Test
    void systemOpsBindingCarriesNoOrganization() {
        tenantContext.runAsSystemOps(() ->
                assertThat(tenantContext.currentOrganization()).isEmpty());
    }

    @Test
    void supplyAsWithOrganizationReturnsTheValueAndRestores() {
        final String result = tenantContext.supplyAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThat(tenantContext.currentOrganization()).contains(ENGINEERING);
            return "scoped";
        });

        assertThat(result).isEqualTo("scoped");
        assertThat(tenantContext.currentOrganization()).isEmpty();
    }

    @Test
    void requireCurrentOrganizationFailsClosedWhenAbsent() {
        assertThatThrownBy(tenantContext::requireCurrentOrganization)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("organization");

        tenantContext.runAs(TenantIds.ACME, () ->
                assertThatThrownBy(tenantContext::requireCurrentOrganization)
                        .isInstanceOf(SecurityException.class)
                        .hasMessageContaining("without organization binding"));
    }

    @Test
    void requireCurrentOrganizationReturnsTheBoundOrganization() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () ->
                assertThat(tenantContext.requireCurrentOrganization()).isEqualTo(ENGINEERING));
    }

    @Test
    void organizationOverloadsRejectNullOrganizationBeforeRunningWork() {
        assertThatThrownBy(() -> tenantContext.runAs(TenantIds.ACME, null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("organization must not be null");

        assertThatThrownBy(() -> tenantContext.supplyAs(TenantIds.ACME, null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("organization must not be null");
    }

    @Test
    void switchingOrganizationInsideActiveTransactionFailsClosed() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatThrownBy(() -> tenantContext.runAs(TenantIds.ACME, LOGISTICS, () -> {}))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot switch organization binding")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void unbindingTheOrganizationInsideActiveTransactionFailsClosed() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatThrownBy(() -> tenantContext.runAs(TenantIds.ACME, () -> {}))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot switch organization binding")
                    .hasMessageContaining("none")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void reenteringTheSameTenantAndOrganizationInsideActiveTransactionIsAllowed() {
        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            TransactionSynchronizationManager.setActualTransactionActive(true);

            assertThatCode(() -> tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {}))
                    .doesNotThrowAnyException();

            TransactionSynchronizationManager.setActualTransactionActive(false);
        });
    }

    @Test
    void restoringAcrossAnOrganizationChangeInsideActiveTransactionFailsClosed() {
        final AtomicBoolean tenantTransactionActive = new AtomicBoolean(false);
        tenantContext = new TenantContext(tenantTransactionActive::get);

        tenantContext.runAs(TenantIds.ACME, ENGINEERING, () -> {
            assertThatThrownBy(() -> tenantContext.runAs(TenantIds.ACME, LOGISTICS,
                    () -> tenantTransactionActive.set(true)))
                    .isInstanceOf(SecurityException.class)
                    .hasMessageContaining("cannot restore tenant binding")
                    .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
            // The failed restore leaves the inner binding in place (fail-closed).
            assertThat(tenantContext.currentOrganization()).contains(LOGISTICS);
            // Release the guard so the outer scope can restore and the test ends clean.
            tenantTransactionActive.set(false);
        });
    }
}
