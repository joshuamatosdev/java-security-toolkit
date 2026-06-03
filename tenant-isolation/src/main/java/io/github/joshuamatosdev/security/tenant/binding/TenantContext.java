package io.github.joshuamatosdev.security.tenant.binding;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Holds the active {@link TenantId} for the current thread. The {@link TenantSessionDataSourceProxy}
 * reads this on every connection borrow to bind the PostgreSQL session.
 *
 * <p>Three fail-closed rules:
 *
 * <ul>
 *   <li>{@link #requireCurrent()} throws if no tenant is bound, so a tenant-scoped operation cannot
 *       silently run without a tenant.
 *   <li>The system-operations tenant — which routes to the read-only bypass-role pool — can be
 *       entered only via {@link #runAsSystemOps}/{@link #supplyAsSystemOps}. Every ordinary entry
 *       point ({@link #runAs}, {@link #supplyAs}) <strong>rejects</strong> it, so system-ops
 *       access can never be activated through a request-style setter.
 *   <li><strong>Tenant before transaction.</strong> A transaction borrows its tenant-bound
 *       connection at begin, so the tenant must be bound <em>before</em> a tenant transaction is
 *       active. Binding the first tenant, or switching to a different tenant, once such a transaction
 *       is active is rejected — the database session is already (or about to be) bound and the change
 *       could not be honored. (Re-entering the already-bound tenant is allowed.) This guard is an
 *       early, clear-error layer; {@link TenantSessionDataSourceProxy} independently fails closed at
 *       borrow time regardless of this guard, so relaxing the check (see
 *       {@link #useTenantTransactionActiveCheck}) never weakens isolation.
 * </ul>
 *
 * <p><strong>Single vs. multi datasource.</strong> "A tenant transaction is active" defaults to
 * {@link TransactionSynchronizationManager#isActualTransactionActive()}, which is correct when the
 * tenant datasource is the only one enlisted on the thread. Deployments with additional datasources
 * should install a narrower check via {@link #useTenantTransactionActiveCheck} so that a transaction
 * on an unrelated datasource does not block tenant binding.
 */
@SystemTenantBoundary
public final class TenantContext {

    private static final ThreadLocal<TenantId> CURRENT = new ThreadLocal<>();

    /**
     * Decides whether a transaction that would have bound the tenant datasource's connection is
     * active on the current thread. Defaults to the single-datasource interpretation (any active
     * transaction is the tenant transaction); replaceable for multi-datasource deployments via
     * {@link #useTenantTransactionActiveCheck}.
     */
    private static volatile BooleanSupplier tenantTransactionActive =
            TransactionSynchronizationManager::isActualTransactionActive;

    /**
     * Prevents construction of the static context holder.
     */
    private TenantContext() {}

    /**
     * Configures how the tenant-before-transaction guard detects an active tenant transaction.
     * Intended to be called once at startup.
     *
     * <ul>
     *   <li><strong>Single datasource</strong> (default):
     *       {@code TransactionSynchronizationManager::isActualTransactionActive} — any active
     *       transaction is the tenant transaction.
     *   <li><strong>Multiple datasources</strong>: a check scoped to the tenant datasource, e.g.
     *       {@code () -> TransactionSynchronizationManager.hasResource(tenantDataSource)}, so a
     *       transaction on an unrelated datasource does not block tenant binding.
     * </ul>
     *
     * <p>Relaxing this check only affects the early, clear-error guard here;
     * {@link TenantSessionDataSourceProxy} still fails closed at borrow time, so isolation is
     * unaffected.
     *
     * @param check predicate that reports whether the tenant datasource transaction is active
     */
    public static void useTenantTransactionActiveCheck(final BooleanSupplier check) {
        tenantTransactionActive = Objects.requireNonNull(check, "check must not be null");
    }

    /**
     * Returns the tenant currently bound to the calling thread.
     *
     * @return the current tenant, or empty when no tenant has been bound
     */
    public static Optional<TenantId> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    /**
     * Returns the current tenant or fails closed when none is bound.
     *
     * @return the tenant currently bound to the calling thread
     * @throws SecurityException when a tenant-scoped operation runs without a tenant
     */
    public static TenantId requireCurrent() {
        final TenantId current = CURRENT.get();
        if (current == null) {
            throw new SecurityException(
                    "TenantContext not populated — tenant-scoped operation attempted without tenant binding");
        }
        return current;
    }

    /**
     * Test-scoped direct setter for ordinary tenants.
     *
     * <p>The method is package-private so production callers use scoped {@link #runAs} /
     * {@link #supplyAs} blocks that restore the prior binding. It still enforces the system-ops and
     * tenant-before-transaction guards because tests must not bypass the real invariants.
     *
     * @param tenant ordinary tenant to bind to the current thread
     */
    static void set(final TenantId tenant) {
        rejectSystemOpsTenant(tenant);
        rejectBindInActiveTransaction(tenant);
        CURRENT.set(tenant);
    }

    /**
     * Clears the current thread's tenant binding.
     *
     * <p>This is intended for test cleanup and infrastructure cleanup paths. Normal application work
     * should prefer scoped methods that restore the prior tenant automatically.
     */
    public static void clear() {
        CURRENT.remove();
    }

    /**
     * Runs work as an ordinary tenant and restores the prior binding afterward.
     *
     * <p>The system-ops tenant is rejected here so request-style code cannot accidentally activate
     * the cross-tenant read pool.
     *
     * @param tenant ordinary tenant to bind for the duration of {@code work}
     * @param work tenant-scoped work to execute
     */
    public static void runAs(final TenantId tenant, final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        rejectSystemOpsTenant(tenant);
        rejectBindInActiveTransaction(tenant);
        final TenantId prior = CURRENT.get();
        CURRENT.set(tenant);
        try {
            work.run();
        } finally {
            restore(prior);
        }
    }

    /**
     * Supplies a value as an ordinary tenant and restores the prior binding afterward.
     *
     * @param tenant ordinary tenant to bind for the duration of {@code work}
     * @param work tenant-scoped supplier to execute
     * @param <T> result type
     * @return the value produced by {@code work}
     */
    public static <T> T supplyAs(final TenantId tenant, final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        rejectSystemOpsTenant(tenant);
        rejectBindInActiveTransaction(tenant);
        final TenantId prior = CURRENT.get();
        CURRENT.set(tenant);
        try {
            return work.get();
        } finally {
            restore(prior);
        }
    }

    /**
     * Runs work as the system-operations tenant.
     *
     * <p>This is the only runnable entry point that may bind {@link TenantIds#SYSTEM_OPS}; the
     * datasource router interprets that binding as permission to use the read-only bypass-role pool.
     *
     * @param work system-operations work to execute
     */
    public static void runAsSystemOps(final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        rejectBindInActiveTransaction(TenantIds.SYSTEM_OPS);
        final TenantId prior = CURRENT.get();
        CURRENT.set(TenantIds.SYSTEM_OPS);
        try {
            work.run();
        } finally {
            restore(prior);
        }
    }

    /**
     * Supplies a value as the system-operations tenant.
     *
     * @param work system-operations supplier to execute
     * @param <T> result type
     * @return the value produced by {@code work}
     */
    public static <T> T supplyAsSystemOps(final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        rejectBindInActiveTransaction(TenantIds.SYSTEM_OPS);
        final TenantId prior = CURRENT.get();
        CURRENT.set(TenantIds.SYSTEM_OPS);
        try {
            return work.get();
        } finally {
            restore(prior);
        }
    }

    /**
     * Blocks the system-operations tenant from ordinary tenant entry points.
     *
     * @param tenant tenant requested by a normal tenant-scoped entry point
     */
    private static void rejectSystemOpsTenant(final TenantId tenant) {
        Objects.requireNonNull(tenant, "tenant must not be null");
        if (TenantIds.SYSTEM_OPS.equals(tenant)) {
            throw new SecurityException("SYSTEM_OPS tenant requires runAsSystemOps or supplyAsSystemOps");
        }
    }

    /**
     * Rejects (re)binding a tenant once a tenant transaction is active — the transaction borrows its
     * tenant-bound connection at the beginning, so the tenant must be bound first. Re-entering the same
     * tenant is allowed; a first bind or a switch is rejected. Whether a tenant transaction is active
     * is decided by the configurable {@link #tenantTransactionActive} check.
     *
     * @param target tenant that the caller wants to bind
     */
    private static void rejectBindInActiveTransaction(final TenantId target) {
        if (!tenantTransactionActive.getAsBoolean()) {
            return;
        }
        final TenantId current = CURRENT.get();
        if (current == null) {
            throw new SecurityException("cannot bind tenant " + target
                    + " inside an active transaction — the transaction borrows a tenant-bound database"
                    + " connection at begin, so the tenant must be bound before the transaction starts"
                    + " (fail-closed)");
        }
        if (!current.equals(target)) {
            throw new SecurityException("cannot switch tenant binding from " + current + " to " + target
                    + " inside an active transaction — the transaction has already borrowed a"
                    + " tenant-bound database session, so the switch could not be enforced (fail-closed)");
        }
    }

    /**
     * Restores a previously bound tenant after scoped work completes.
     *
     * <p>Removing the thread-local when there was no prior tenant avoids leaking a completed request's
     * tenant into later work on the same thread.
     *
     * @param prior tenant that was bound before the scoped work, or {@code null} when none existed
     */
    private static void restore(final @Nullable TenantId prior) {
        if (prior == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(prior);
        }
    }
}
