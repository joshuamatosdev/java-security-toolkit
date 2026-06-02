package io.github.joshuamatosdev.security.tenant;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;
import java.util.UUID;
import java.util.concurrent.Executor;
import javax.sql.DataSource;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Binds PostgreSQL session variables {@code app.current_tenant} and {@code app.bypass_rls} on every
 * Spring-managed connection borrow so that per-table RLS policies evaluate against the active
 * {@link TenantContext}.
 *
 * <p>Inside an active physical JDBC transaction, transaction-local bindings are used and clear
 * automatically at commit or rollback. Otherwise the settings are issued as session-scoped bindings
 * and the returned connection is wrapped so {@link Connection#close()} clears them before the
 * connection returns to the pool.
 *
 * <p>Fail-closed: if no {@link TenantContext} is populated at borrow time, borrowing throws
 * {@link IllegalStateException} before any SQL can run.
 */
@SystemTenantBoundary
public final class TenantSessionDataSourceProxy extends DelegatingDataSource {

    private static final String SET_CONFIG_SQL = "SELECT set_config(?, ?, ?)";
    private static final Executor DIRECT_EXECUTOR = Runnable::run;

    private final String poolName;
    private final TenantBindingObserver observer;

    public TenantSessionDataSourceProxy(final DataSource delegate, final String poolName) {
        this(delegate, poolName, TenantBindingObserver.NOOP);
    }

    public TenantSessionDataSourceProxy(
            final DataSource delegate, final String poolName, final TenantBindingObserver observer) {
        super(delegate);
        this.poolName = poolName;
        this.observer = observer;
    }

    public String poolName() {
        return poolName;
    }

    @Override
    public Connection getConnection() throws SQLException {
        return bind(super.getConnection());
    }

    @Override
    public Connection getConnection(final String username, final String password) throws SQLException {
        return bind(super.getConnection(username, password));
    }

    private Connection bind(final Connection raw) throws SQLException {
        final UUID tenantUuid = requireTenantOrFail(raw);
        final boolean bypass = tenantUuid.equals(TenantIds.SYSTEM_OPS.value());
        final boolean local = shouldUseTransactionLocalBinding(raw);
        applyBinding(raw, tenantUuid, bypass, local);
        observer.onBindingSet(poolName);
        if (local) {
            return raw;
        }
        return wrapForSessionReset(raw);
    }

    private static boolean shouldUseTransactionLocalBinding(final Connection raw) throws SQLException {
        return TransactionSynchronizationManager.isActualTransactionActive() && !raw.getAutoCommit();
    }

    private UUID requireTenantOrFail(final Connection raw) throws SQLException {
        if (TenantContext.current().isEmpty()) {
            observer.onBindingMissing(poolName);
            try {
                raw.close();
            } catch (SQLException suppressed) {
                // ignore; we are already failing fast
            }
            throw new IllegalStateException("TenantContext not populated — tenant-scoped datasource '" + poolName
                    + "' requires tenant binding");
        }
        return TenantContext.requireCurrent().value();
    }

    private static void applyBinding(
            final Connection raw, final UUID tenantUuid, final boolean bypass, final boolean local)
            throws SQLException {
        setConfig(raw, "app.current_tenant", tenantUuid.toString(), local);
        setConfig(raw, "app.bypass_rls", bypass ? "on" : "off", local);
    }

    private static void setConfig(final Connection raw, final String name, final String value, final boolean local)
            throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            stmt.setString(1, name);
            stmt.setString(2, value);
            stmt.setBoolean(3, local);
            stmt.execute();
        }
    }

    private static void clearConfig(final Connection raw, final String name) throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            stmt.setString(1, name);
            stmt.setNull(2, Types.VARCHAR);
            stmt.setBoolean(3, false);
            stmt.execute();
        }
    }

    private Connection wrapForSessionReset(final Connection raw) {
        return (Connection) Proxy.newProxyInstance(
                TenantSessionDataSourceProxy.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                new SessionResetHandler(raw, poolName, observer));
    }

    private static final class SessionResetHandler implements InvocationHandler {
        private final Connection delegate;
        private final String poolName;
        private final TenantBindingObserver observer;

        SessionResetHandler(final Connection delegate, final String poolName, final TenantBindingObserver observer) {
            this.delegate = delegate;
            this.poolName = poolName;
            this.observer = observer;
        }

        @Override
        public @Nullable Object invoke(final Object proxy, final Method method, final @Nullable Object[] args)
                throws Throwable {
            if ("close".equals(method.getName()) && (args == null || args.length == 0)) {
                try {
                    clearConfig(delegate, "app.current_tenant");
                    clearConfig(delegate, "app.bypass_rls");
                } catch (SQLException ex) {
                    observer.onResetFailed(poolName);
                    delegate.abort(DIRECT_EXECUTOR);
                    return null;
                }
                delegate.close();
                return null;
            }
            try {
                return method.invoke(delegate, args);
            } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
            }
        }
    }
}
