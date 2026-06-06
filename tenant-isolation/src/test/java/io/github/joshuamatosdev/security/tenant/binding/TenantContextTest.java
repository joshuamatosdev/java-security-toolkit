package io.github.joshuamatosdev.security.tenant.binding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.testfixtures.WithTenant;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Unit tests for the fail-closed invariants of {@link TenantContext}:
 *
 * <ol>
 *   <li>the system-operations tenant cannot be entered through the ordinary {@code set} setter — it
 *       routes to the read-only bypass-role pool, so allowing it there would be a system-ops access
 *       footgun;
 *   <li>tenant before transaction: once a tenant transaction is active, a first bind or a switch to a
 *       different tenant is rejected (the connection is already, or about to be, bound) — better to
 *       fail closed than run under the wrong tenant;
 *   <li>the "tenant transaction active" check is configurable, so a multi-datasource deployment can
 *       scope it to the tenant datasource.
 * </ol>
 *
 * <p>Why this is important to test: tenant context leaks or late binding can put the next request
 * under the wrong tenant.
 */
class TenantContextTest {

    private static final String ACTIVE_TRANSACTION_MESSAGE = "active transaction";

    @AfterEach
    void reset() {
        TransactionSynchronizationManager.setActualTransactionActive(false);
        TenantContext.useTenantTransactionActiveCheck(() -> false);
        TenantContext.clear();
        TenantContext.resetTenantTransactionActiveCheck();
    }

    @Test
    void setRejectsTheSystemOpsTenant() {
        assertThatThrownBy(() -> TenantContext.set(TenantIds.SYSTEM_OPS))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("runAsSystemOps");
    }

    @Test
    void ordinaryTenantEntryPointsRejectNullTenantBeforeRunningWork() {
        assertThatThrownBy(() -> TenantContext.runAs(null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenant must not be null");

        assertThatThrownBy(() -> TenantContext.supplyAs(null, () -> {
            throw new AssertionError("work must not run");
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("tenant must not be null");
    }

    @Test
    void tenantEntryPointsRejectNullWorkBeforeChangingContext() {
        TenantContext.set(TenantIds.ACME);

        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.GLOBEX, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("work must not be null");
        assertThat(TenantContext.current()).contains(TenantIds.ACME);

        assertThatThrownBy(() -> TenantContext.runAsSystemOps(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("work must not be null");
        assertThat(TenantContext.current()).contains(TenantIds.ACME);
    }

    @Test
    void switchingTenantViaSetInsideActiveTransactionFailsClosed() {
        TenantContext.set(TenantIds.ACME);
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(() -> TenantContext.set(TenantIds.GLOBEX))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
    }

    @Test
    void switchingTenantViaRunAsInsideActiveTransactionFailsClosed() {
        TenantContext.set(TenantIds.ACME);
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.GLOBEX, () -> {}))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
    }

    @Test
    void enteringSystemOpsInsideActiveTransactionFailsClosed() {
        TenantContext.set(TenantIds.ACME);
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(() -> TenantContext.runAsSystemOps(() -> {}))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
    }

    @Test
    void reenteringTheSameTenantInsideActiveTransactionIsAllowed() {
        TenantContext.set(TenantIds.ACME);
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatCode(() -> TenantContext.runAs(TenantIds.ACME, () -> {})).doesNotThrowAnyException();
    }

    @Test
    void switchingTenantWithoutAnActiveTransactionIsAllowed() {
        TenantContext.set(TenantIds.ACME);

        assertThatCode(() -> TenantContext.runAs(TenantIds.GLOBEX, () -> {})).doesNotThrowAnyException();
    }

    @Test
    void bindingTheFirstTenantInsideAnActiveTransactionIsRejected() {
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(() -> TenantContext.set(TenantIds.ACME))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("before the transaction starts");
    }

    @Test
    void aMultiDatasourceCheckReportingTheTenantDatasourceIdleAllowsBinding() {
        // Multi-datasource deployment: a transaction is active on the thread, but it belongs to an
        // unrelated datasource, so the tenant-scoped check reports "not a tenant transaction" and
        // binding the tenant is permitted (the datasource proxy still fails closed if the tenant pool
        // is later borrowed without a tenant).
        TransactionSynchronizationManager.setActualTransactionActive(true);
        TenantContext.useTenantTransactionActiveCheck(() -> false);

        assertThatCode(() -> TenantContext.set(TenantIds.ACME)).doesNotThrowAnyException();
    }

    @Test
    void clearingTenantInsideActiveTransactionFailsClosedAndKeepsBinding() {
        TenantContext.set(TenantIds.ACME);
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(TenantContext::clear)
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("cannot clear tenant binding")
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
        assertThat(TenantContext.current()).contains(TenantIds.ACME);
    }

    @Test
    void restoringToNoTenantInsideActiveTransactionFailsClosedAndKeepsBinding() {
        final AtomicBoolean tenantTransactionActive = new AtomicBoolean(false);
        TenantContext.useTenantTransactionActiveCheck(tenantTransactionActive::get);

        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.ACME, () -> tenantTransactionActive.set(true)))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("cannot restore tenant binding")
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
        assertThat(TenantContext.current()).contains(TenantIds.ACME);
    }

    @Test
    void restoringPriorTenantInsideActiveTransactionFailsClosedAndKeepsInnerBinding() {
        final AtomicBoolean tenantTransactionActive = new AtomicBoolean(false);
        TenantContext.useTenantTransactionActiveCheck(tenantTransactionActive::get);
        TenantContext.set(TenantIds.ACME);

        assertThatThrownBy(() -> TenantContext.runAs(TenantIds.GLOBEX, () -> tenantTransactionActive.set(true)))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("cannot restore tenant binding")
                .hasMessageContaining(ACTIVE_TRANSACTION_MESSAGE);
        assertThat(TenantContext.current()).contains(TenantIds.GLOBEX);
    }

    @Test
    void testFixtureRestoresPriorSystemOpsContext() {
        TenantContext.runAsSystemOps(() -> {
            WithTenant.runAs(TenantIds.ACME, () -> assertThat(TenantContext.current()).contains(TenantIds.ACME));

            assertThat(TenantContext.current()).contains(TenantIds.SYSTEM_OPS);
        });

        assertThat(TenantContext.current()).isEmpty();
    }
}
