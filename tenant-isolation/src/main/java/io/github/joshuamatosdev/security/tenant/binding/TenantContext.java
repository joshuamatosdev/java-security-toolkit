package io.github.joshuamatosdev.security.tenant.binding;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Instance-scoped tenant binding context.
 *
 * <p>Each application context owns one instance. The datasource boundary receives the same instance
 * through {@link TenantBindingSource}; no process-wide mutable policy or ambient singleton is used.
 */
@SystemTenantBoundary
public final class TenantContext implements TenantBindingSource {

    private final ThreadLocal<TenantBinding> current = new ThreadLocal<>();
    private final BooleanSupplier tenantTransactionActive;

    /** Uses Spring's single-datasource transaction activity check. */
    public TenantContext() {
        this(TransactionSynchronizationManager::isActualTransactionActive);
    }

    /** Uses an application-specific tenant transaction activity check. */
    public TenantContext(final BooleanSupplier tenantTransactionActive) {
        this.tenantTransactionActive =
                Objects.requireNonNull(tenantTransactionActive, "tenantTransactionActive must not be null");
    }

    @Override
    public Optional<TenantBinding> currentBinding() {
        return Optional.ofNullable(current.get());
    }

    /** Test/infrastructure setter; application work should prefer scoped methods. */
    void set(final TenantId tenant) {
        final TenantBinding target = ordinary(TenantBinding.tenant(tenant));
        requireAllowed(BindingTransition.bindViolation(current.get(), target, transactionActive()));
        current.set(target);
    }

    public void clear() {
        requireAllowed(BindingTransition.clearViolation(current.get(), transactionActive()));
        current.remove();
    }

    public void runAs(final TenantId tenant, final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        scoped(ordinary(TenantBinding.tenant(tenant)), () -> {
            work.run();
            return null;
        });
    }

    public void runAs(
            final TenantId tenant, final OrganizationId organization, final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        scoped(ordinary(TenantBinding.tenantAndOrganization(tenant, organization)), () -> {
            work.run();
            return null;
        });
    }

    public <T> T supplyAs(final TenantId tenant, final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        return scoped(ordinary(TenantBinding.tenant(tenant)), work);
    }

    public <T> T supplyAs(
            final TenantId tenant, final OrganizationId organization, final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        return scoped(ordinary(TenantBinding.tenantAndOrganization(tenant, organization)), work);
    }

    public void runAsSystemOps(final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        scoped(TenantBinding.systemOps(), () -> {
            work.run();
            return null;
        });
    }

    public <T> T supplyAsSystemOps(final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        return scoped(TenantBinding.systemOps(), work);
    }

    private <T> T scoped(final TenantBinding target, final Supplier<T> work) {
        requireAllowed(BindingTransition.bindViolation(current.get(), target, transactionActive()));
        final TenantBinding prior = current.get();
        current.set(target);
        try {
            final T result = work.get();
            restore(prior);
            return result;
        } catch (RuntimeException | Error ex) {
            restoreSuppressing(prior, ex);
            throw ex;
        }
    }

    private void restoreSuppressing(final @Nullable TenantBinding prior, final Throwable primary) {
        try {
            restore(prior);
        } catch (RuntimeException restoreFailure) {
            primary.addSuppressed(restoreFailure);
        }
    }

    private void restore(final @Nullable TenantBinding prior) {
        requireAllowed(BindingTransition.restoreViolation(current.get(), prior, transactionActive()));
        if (prior == null) {
            current.remove();
        } else {
            current.set(prior);
        }
    }

    private static TenantBinding ordinary(final TenantBinding binding) {
        if (binding.isSystemOps()) {
            throw new SecurityException("SYSTEM_OPS tenant requires runAsSystemOps or supplyAsSystemOps");
        }
        return binding;
    }

    private boolean transactionActive() {
        return tenantTransactionActive.getAsBoolean();
    }

    private static void requireAllowed(final Optional<String> violation) {
        violation.ifPresent(message -> {
            throw new SecurityException(message);
        });
    }
}
