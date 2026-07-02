package io.github.joshuamatosdev.security.tenant.binding;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.datasource.session.TenantSessionDataSourceProxy;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Holds the active {@link TenantId} — and, when bound, the actor's {@link OrganizationId} within
 * that tenant — for the current thread. The {@link TenantSessionDataSourceProxy} reads this on
 * every connection borrow to bind the PostgreSQL session.
 *
 * <p>The organization is a dimension of the tenant binding, never a separate binding: it is set
 * and restored atomically with the tenant through the two-argument {@link #runAs(TenantId,
 * OrganizationId, Runnable)} / {@link #supplyAs(TenantId, OrganizationId, Supplier)} entry points,
 * so tenant and organization can never skew. The system-operations tenant carries no organization
 * because cross-tenant operational work is not organization-scoped.
 *
 * <p>Three fail-closed rules:
 *
 * <ul>
 *   <li>{@link #requireCurrent()} throws if no tenant is bound, so a tenant-scoped operation cannot
 *       silently run without a tenant. {@link #requireCurrentOrganization()} does the same for the
 *       organization dimension.
 *   <li>The system-operations tenant — which routes to the read-only bypass-role pool — can be
 *       entered only via {@link #runAsSystemOps}/{@link #supplyAsSystemOps}. Every ordinary entry
 *       point ({@link #runAs}, {@link #supplyAs}) <strong>rejects</strong> it, so system-ops
 *       access can never be activated through a request-style setter.
 *   <li><strong>Tenant before transaction.</strong> A transaction borrows its tenant-bound
 *       connection at begin, so the tenant must be bound <em>before</em> a tenant transaction is
 *       active. Binding the first tenant, switching to a different tenant, or switching the
 *       organization dimension once such a transaction is active is rejected — the database session
 *       is already (or about to be) bound and the change could not be honored. (Re-entering the
 *       already-bound tenant and organization is allowed.) This guard is an early, clear-error
 *       layer; {@link TenantSessionDataSourceProxy} independently fails closed at borrow time
 *       regardless of this guard, so relaxing the check (see
 *       {@link #useTenantTransactionActiveCheck}) never weakens isolation.
 * </ul>
 *
 * <p><strong>Single vs. multi datasource.</strong> "A tenant transaction is active" defaults to
 * {@link TransactionSynchronizationManager#isActualTransactionActive()}, which is correct when the
 * tenant datasource is the only one enlisted on the thread. Deployments with additional datasources
 * should install a narrower check via {@link #useTenantTransactionActiveCheck} so that a transaction
 * on an unrelated datasource does not block tenant binding.
 *
 * <p>Why this exists: tenant binding is the handoff from request identity to database/session
 * controls and must be centralized rather than rebuilt ad hoc.
 */
@SystemTenantBoundary
public final class TenantContext {

    /**
     * One thread's tenant binding. The organization rides inside the same value so the two
     * dimensions are set, restored, and cleared as a unit.
     *
     * @param tenant the bound tenant
     * @param organization the actor's organization within the tenant, or {@code null} when the
     *     binding is tenant-only
     */
    private record Binding(TenantId tenant, @Nullable OrganizationId organization) {}

    private static final ThreadLocal<Binding> CURRENT = new ThreadLocal<>();

    /**
     * Decides whether a transaction that would have bound the tenant datasource's connection is
     * active on the current thread. Defaults to the single-datasource interpretation (any active
     * transaction is the tenant transaction); replaceable for multi-datasource deployments via
     * {@link #useTenantTransactionActiveCheck}.
     */
    private static final BooleanSupplier DEFAULT_TENANT_TRANSACTION_ACTIVE_CHECK =
            TransactionSynchronizationManager::isActualTransactionActive;
    private static volatile BooleanSupplier tenantTransactionActive =
            DEFAULT_TENANT_TRANSACTION_ACTIVE_CHECK;

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
     * Restores the default single-datasource tenant transaction check.
     *
     * <p>This is primarily useful for reusable test contracts and infrastructure cleanup after a
     * scoped override. It returns the guard to {@link
     * TransactionSynchronizationManager#isActualTransactionActive()} rather than leaving a permissive
     * test predicate in process-wide static state.
     */
    public static void resetTenantTransactionActiveCheck() {
        tenantTransactionActive = DEFAULT_TENANT_TRANSACTION_ACTIVE_CHECK;
    }

    /**
     * Returns the tenant currently bound to the calling thread.
     *
     * @return the current tenant, or empty when no tenant has been bound
     */
    public static Optional<TenantId> current() {
        return Optional.ofNullable(CURRENT.get()).map(Binding::tenant);
    }

    /**
     * Returns the organization dimension of the current binding.
     *
     * @return the current organization, or empty when no binding exists or the binding is
     *     tenant-only
     */
    public static Optional<OrganizationId> currentOrganization() {
        return Optional.ofNullable(CURRENT.get()).map(Binding::organization);
    }

    /**
     * Returns the current tenant or fails closed when none is bound.
     *
     * @return the tenant currently bound to the calling thread
     * @throws SecurityException when a tenant-scoped operation runs without a tenant
     */
    public static TenantId requireCurrent() {
        final Binding current = CURRENT.get();
        if (current == null) {
            throw new SecurityException(
                    "TenantContext not populated — tenant-scoped operation attempted without tenant binding");
        }
        return current.tenant();
    }

    /**
     * Returns the organization dimension of the current binding or fails closed when absent.
     *
     * @return the organization currently bound to the calling thread
     * @throws SecurityException when an organization-scoped operation runs without an organization
     */
    public static OrganizationId requireCurrentOrganization() {
        final Binding current = CURRENT.get();
        if (current == null || current.organization() == null) {
            throw new SecurityException("TenantContext organization not populated — organization-scoped"
                    + " operation attempted without organization binding");
        }
        return current.organization();
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
        rejectBindInActiveTransaction(tenant, null);
        CURRENT.set(new Binding(tenant, null));
    }

    /**
     * Clears the current thread's tenant binding, including its organization dimension.
     *
     * <p>This is intended for test cleanup and infrastructure cleanup paths. Normal application work
     * should prefer scoped methods that restore the prior tenant automatically. Clearing is rejected
     * while a tenant transaction is active because the database connection may already carry the
     * prior signed tenant claim; removing the thread-local at that point would desynchronize the
     * application boundary from the database session.
     */
    public static void clear() {
        rejectClearInActiveTransaction();
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
        scoped(tenant, null, () -> {
            work.run();
            return null;
        });
    }

    /**
     * Runs work as an ordinary tenant with an organization dimension and restores the prior binding
     * afterward.
     *
     * <p>The organization is bound atomically with the tenant: there is deliberately no entry point
     * that binds an organization alone, so the organization can never outlive or precede its tenant.
     *
     * @param tenant ordinary tenant to bind for the duration of {@code work}
     * @param organization the actor's organization within {@code tenant}
     * @param work tenant- and organization-scoped work to execute
     */
    public static void runAs(final TenantId tenant, final OrganizationId organization, final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        Objects.requireNonNull(organization, "organization must not be null");
        scoped(tenant, organization, () -> {
            work.run();
            return null;
        });
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
        return scoped(tenant, null, work);
    }

    /**
     * Supplies a value as an ordinary tenant with an organization dimension and restores the prior
     * binding afterward.
     *
     * @param tenant ordinary tenant to bind for the duration of {@code work}
     * @param organization the actor's organization within {@code tenant}
     * @param work tenant- and organization-scoped supplier to execute
     * @param <T> result type
     * @return the value produced by {@code work}
     */
    public static <T> T supplyAs(
            final TenantId tenant, final OrganizationId organization, final Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        Objects.requireNonNull(organization, "organization must not be null");
        return scoped(tenant, organization, work);
    }

    /**
     * Runs work as the system-operations tenant.
     *
     * <p>This is the only runnable entry point that may bind {@link TenantIds#SYSTEM_OPS}; the
     * datasource router interprets that binding as permission to use the read-only bypass-role pool.
     * The system-ops binding never carries an organization.
     *
     * @param work system-operations work to execute
     */
    public static void runAsSystemOps(final Runnable work) {
        Objects.requireNonNull(work, "work must not be null");
        systemOpsScoped(() -> {
            work.run();
            return null;
        });
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
        return systemOpsScoped(work);
    }

    /**
     * Binds an ordinary tenant (with an optional organization dimension) around {@code work} and
     * restores the prior binding afterward.
     *
     * @param tenant ordinary tenant to bind
     * @param organization organization dimension, or {@code null} for a tenant-only binding
     * @param work scoped work to execute
     * @param <T> result type
     * @return the value produced by {@code work}
     */
    private static <T> T scoped(
            final TenantId tenant, final @Nullable OrganizationId organization, final Supplier<T> work) {
        rejectSystemOpsTenant(tenant);
        rejectBindInActiveTransaction(tenant, organization);
        final Binding prior = CURRENT.get();
        CURRENT.set(new Binding(tenant, organization));
        try {
            final T result = work.get();
            restore(prior);
            return result;
        } catch (final RuntimeException | Error ex) {
            restoreSuppressing(prior, ex);
            throw ex;
        }
    }

    /**
     * Binds the system-operations tenant around {@code work} and restores the prior binding.
     *
     * @param work system-operations work to execute
     * @param <T> result type
     * @return the value produced by {@code work}
     */
    private static <T> T systemOpsScoped(final Supplier<T> work) {
        rejectBindInActiveTransaction(TenantIds.SYSTEM_OPS, null);
        final Binding prior = CURRENT.get();
        CURRENT.set(new Binding(TenantIds.SYSTEM_OPS, null));
        try {
            final T result = work.get();
            restore(prior);
            return result;
        } catch (final RuntimeException | Error ex) {
            restoreSuppressing(prior, ex);
            throw ex;
        }
    }

    /**
     * Restores the prior binding after failed scoped work without masking the failure.
     *
     * <p>The restore guard can itself throw (a tenant transaction is active and the binding
     * differs) — and the likeliest way to reach that state is the work failing mid-transaction.
     * The work's exception is the root cause an operator needs, so a restore failure is attached
     * as suppressed instead of replacing it. The fail-closed outcome is unchanged: the inner
     * binding is retained, exactly as when restore throws on the success path.
     *
     * @param prior binding to restore
     * @param primary the exception thrown by the scoped work
     */
    private static void restoreSuppressing(final @Nullable Binding prior, final Throwable primary) {
        try {
            restore(prior);
        } catch (final RuntimeException restoreFailure) {
            primary.addSuppressed(restoreFailure);
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
     * Rejects (re)binding once a tenant transaction is active — the transaction borrows its
     * tenant-bound connection at the beginning, so the binding must be complete first. Re-entering
     * the same tenant and organization is allowed; a first bind, a tenant switch, or an organization
     * switch is rejected. Whether a tenant transaction is active is decided by the configurable
     * {@link #tenantTransactionActive} check.
     *
     * @param targetTenant tenant that the caller wants to bind
     * @param targetOrganization organization dimension that the caller wants to bind, or {@code null}
     */
    private static void rejectBindInActiveTransaction(
            final TenantId targetTenant, final @Nullable OrganizationId targetOrganization) {
        if (!tenantTransactionActive.getAsBoolean()) {
            return;
        }
        final Binding current = CURRENT.get();
        if (current == null) {
            throw new SecurityException("cannot bind tenant " + targetTenant
                    + " inside an active transaction — the transaction borrows a tenant-bound database"
                    + " connection at begin, so the tenant must be bound before the transaction starts"
                    + " (fail-closed)");
        }
        if (!current.tenant().equals(targetTenant)) {
            throw new SecurityException("cannot switch tenant binding from " + current.tenant() + " to "
                    + targetTenant
                    + " inside an active transaction — the transaction has already borrowed a"
                    + " tenant-bound database session, so the switch could not be enforced (fail-closed)");
        }
        if (!Objects.equals(current.organization(), targetOrganization)) {
            throw new SecurityException("cannot switch organization binding from "
                    + describeOrganization(current.organization()) + " to "
                    + describeOrganization(targetOrganization)
                    + " inside an active transaction — the transaction has already borrowed a"
                    + " tenant-bound database session, so the switch could not be enforced (fail-closed)");
        }
    }

    /**
     * Rejects clearing the current tenant while a tenant transaction is active.
     */
    private static void rejectClearInActiveTransaction() {
        final Binding current = CURRENT.get();
        if (current != null && tenantTransactionActive.getAsBoolean()) {
            throw new SecurityException("cannot clear tenant binding for " + current.tenant()
                    + " inside an active transaction — the transaction may already hold a"
                    + " tenant-bound database session, so clearing the application boundary could"
                    + " desynchronize it from the database session (fail-closed)");
        }
    }

    /**
     * Restores a previously bound tenant (and organization dimension) after scoped work completes.
     *
     * <p>Removing the thread-local when there was no prior binding avoids leaking a completed
     * request's tenant into later work on the same thread.
     *
     * @param prior binding that existed before the scoped work, or {@code null} when none existed
     */
    private static void restore(final @Nullable Binding prior) {
        final Binding current = CURRENT.get();
        if (tenantTransactionActive.getAsBoolean() && !Objects.equals(current, prior)) {
            throw new SecurityException("cannot restore tenant binding from " + describeBinding(current)
                    + " to " + describeBinding(prior)
                    + " inside an active transaction — the transaction may already hold a"
                    + " tenant-bound database session, so restoring the application boundary could"
                    + " desynchronize it from the database session (fail-closed)");
        }
        if (prior == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(prior);
        }
    }

    /**
     * Renders a binding for guard messages.
     *
     * @param binding binding to describe, possibly {@code null}
     * @return tenant plus organization dimension, or {@code "none"} when no binding exists
     */
    private static String describeBinding(final @Nullable Binding binding) {
        if (binding == null) {
            return "none";
        }
        if (binding.organization() == null) {
            return binding.tenant().toString();
        }
        return binding.tenant() + " (organization " + binding.organization() + ")";
    }

    /**
     * Renders an organization dimension for guard messages.
     *
     * @param organization organization to describe, possibly {@code null}
     * @return the organization identifier or {@code "none"}
     */
    private static String describeOrganization(final @Nullable OrganizationId organization) {
        return organization == null ? "none" : organization.toString();
    }
}
