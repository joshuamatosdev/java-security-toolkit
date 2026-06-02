package io.github.joshuamatosdev.security.tenant.binding;

import java.util.Optional;
import java.util.function.Supplier;
import org.jspecify.annotations.Nullable;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;

/**
 * Holds the active {@link TenantId} for the current thread. The {@link TenantSessionDataSourceProxy}
 * reads this on every connection borrow to bind the PostgreSQL session.
 *
 * <p>Fail-closed: {@link #requireCurrent()} throws if no tenant is bound, so a tenant-scoped
 * operation cannot silently run without a tenant. The system-operations tenant must be entered via
 * {@link #runAsSystemOps}/{@link #supplyAsSystemOps} — the ordinary {@code runAs}/{@code supplyAs}
 * paths reject it.
 */
@SystemTenantBoundary
public final class TenantContext {

    private static final ThreadLocal<TenantId> CURRENT = new ThreadLocal<>();
    private static final ThreadLocal<TenantBindingScope> CURRENT_SCOPE = new ThreadLocal<>();

    private TenantContext() {}

    public static Optional<TenantId> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    public static TenantId requireCurrent() {
        final TenantId current = CURRENT.get();
        if (current == null) {
            throw new SecurityException(
                    "TenantContext not populated — tenant-scoped operation attempted without tenant binding");
        }
        return current;
    }

    public static void set(final TenantId tenant) {
        CURRENT.set(tenant);
        CURRENT_SCOPE.set(TenantBindingScope.UNBOUNDED);
    }

    public static void clear() {
        CURRENT.remove();
        CURRENT_SCOPE.remove();
    }

    public static void runAs(final TenantId tenant, final Runnable work) {
        rejectSystemOpsTenant(tenant);
        final TenantId prior = CURRENT.get();
        final TenantBindingScope priorScope = CURRENT_SCOPE.get();
        bind(tenant, TenantBindingScope.BOUNDED);
        try {
            work.run();
        } finally {
            restore(prior, priorScope);
        }
    }

    public static <T> T supplyAs(final TenantId tenant, final Supplier<T> work) {
        rejectSystemOpsTenant(tenant);
        final TenantId prior = CURRENT.get();
        final TenantBindingScope priorScope = CURRENT_SCOPE.get();
        bind(tenant, TenantBindingScope.BOUNDED);
        try {
            return work.get();
        } finally {
            restore(prior, priorScope);
        }
    }

    public static void runAsSystemOps(final Runnable work) {
        final TenantId prior = CURRENT.get();
        final TenantBindingScope priorScope = CURRENT_SCOPE.get();
        bind(TenantIds.SYSTEM_OPS, TenantBindingScope.BOUNDED);
        try {
            work.run();
        } finally {
            restore(prior, priorScope);
        }
    }

    public static <T> T supplyAsSystemOps(final Supplier<T> work) {
        final TenantId prior = CURRENT.get();
        final TenantBindingScope priorScope = CURRENT_SCOPE.get();
        bind(TenantIds.SYSTEM_OPS, TenantBindingScope.BOUNDED);
        try {
            return work.get();
        } finally {
            restore(prior, priorScope);
        }
    }

    public static boolean isCurrentBindingBounded() {
        return CURRENT_SCOPE.get() == TenantBindingScope.BOUNDED;
    }

    private static void bind(final TenantId tenant, final TenantBindingScope scope) {
        CURRENT.set(tenant);
        CURRENT_SCOPE.set(scope);
    }

    private static void rejectSystemOpsTenant(final TenantId tenant) {
        if (TenantIds.SYSTEM_OPS.equals(tenant)) {
            throw new SecurityException("SYSTEM_OPS tenant requires runAsSystemOps or supplyAsSystemOps");
        }
    }

    private static void restore(final @Nullable TenantId prior, final @Nullable TenantBindingScope priorScope) {
        if (prior == null) {
            CURRENT.remove();
            CURRENT_SCOPE.remove();
        } else {
            CURRENT.set(prior);
            if (priorScope == null) {
                CURRENT_SCOPE.remove();
            } else {
                CURRENT_SCOPE.set(priorScope);
            }
        }
    }
}
