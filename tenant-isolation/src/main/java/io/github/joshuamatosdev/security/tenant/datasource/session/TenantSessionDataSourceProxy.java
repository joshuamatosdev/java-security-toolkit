package io.github.joshuamatosdev.security.tenant.datasource.session;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.ConnectionBuilder;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.ShardingKeyBuilder;
import java.sql.Types;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import javax.sql.DataSource;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingObserver;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Binds PostgreSQL session variable {@code app.tenant_claim} on every Spring-managed connection
 * borrow so that per-table RLS policies evaluate against the active {@link TenantContext}.
 *
 * <p>The setting is a signed claim, not the tenant authority by itself. PostgreSQL verifies the
 * HMAC with a DB-private secret before RLS trusts it. The returned connection is wrapped so {@link
 * Connection#close()} clears the claim before the connection returns to the pool.
 *
 * <p>Fail-closed: if no {@link TenantContext} is populated at borrow time, borrowing throws
 * {@link IllegalStateException} before any SQL can run.
 */
@SystemTenantBoundary
public final class TenantSessionDataSourceProxy extends AbstractDataSource implements TenantPoolInspection, AutoCloseable {

    private static final String SET_CONFIG_SQL = "SELECT set_config(?, ?, ?)";
    private static final String TENANT_CLAIM_SETTING = "app.tenant_claim";
    private static final String ARGS_REQUIRED = "args";
    private static final String WRAPPER_INTERFACE_REQUIRED = "wrapper interface must not be null";
    private static final Executor DIRECT_EXECUTOR = Runnable::run;

    private final DataSource delegate;
    private final String poolName;
    private final TenantClaimSigner claimSigner;
    private final TenantBindingObserver observer;
    private final TenantPoolInspection poolInspection;

    /**
     * Creates a tenant-binding datasource proxy with no-op observability callbacks.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant claim that PostgreSQL verifies inside RLS policies
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate, final String poolName, final TenantClaimSigner claimSigner) {
        this(delegate, poolName, claimSigner, TenantBindingObserver.NOOP, TenantPoolInspection.NONE);
    }

    /**
     * Creates a tenant-binding datasource proxy with a read-only pool inspection capability.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant claim that PostgreSQL verifies inside RLS policies
     * @param poolInspection exposes read-only pool state for trusted infrastructure
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantPoolInspection poolInspection) {
        this(delegate, poolName, claimSigner, TenantBindingObserver.NOOP, poolInspection);
    }

    /**
     * Creates a tenant-binding datasource proxy with explicit observability callbacks.
     *
     * <p>The delegate is intentionally wrapped at the datasource boundary, so every borrow, including
     * JPA and raw JDBC paths that use this bean, receives the same fail-closed tenant binding.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant claim that PostgreSQL verifies inside RLS policies
     * @param observer receives binding, missing-binding, and reset-failure events
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantBindingObserver observer) {
        this(delegate, poolName, claimSigner, observer, TenantPoolInspection.NONE);
    }

    /**
     * Creates a tenant-binding datasource proxy with explicit observability and inspection callbacks.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant claim that PostgreSQL verifies inside RLS policies
     * @param observer receives binding, missing-binding, and reset-failure events
     * @param poolInspection exposes read-only pool state for trusted infrastructure
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantBindingObserver observer,
            final TenantPoolInspection poolInspection) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.poolName = Objects.requireNonNull(poolName, "poolName");
        this.claimSigner = Objects.requireNonNull(claimSigner, "claimSigner");
        this.observer = Objects.requireNonNull(observer, "observer");
        this.poolInspection = Objects.requireNonNull(poolInspection, "poolInspection");
    }

    /**
     * Returns the logical pool name used in observer callbacks.
     *
     * @return the configured pool name
     */
    public String poolName() {
        return poolName;
    }

    @Override
    public List<TenantPoolSnapshot> snapshots() {
        return poolInspection.snapshots();
    }

    /**
     * Signs the current tenant claim, borrows a connection, and immediately binds the claim to the
     * PostgreSQL session.
     *
     * <p>Fail-closed behavior is enforced before the caller receives the connection: if no
     * {@link TenantContext} exists, no connection is borrowed and no SQL can run.
     *
     * @return a guarded connection whose {@link Connection#close()} clears the tenant claim
     * @throws SQLException when borrowing or binding, the underlying connection fails
     */
    @Override
    public @NonNull Connection getConnection() throws SQLException {
        final String tenantClaim = requireTenantClaimOrFail();
        return bind(delegate.getConnection(), tenantClaim);
    }

    /**
     * Rejects caller-supplied credentials for tenant-scoped work.
     *
     * <p>Allowing credentials here would let a caller sidestep the configured non-superuser pool
     * identity, which is the database-side invariant that makes RLS meaningful.
     *
     * @param username ignored because per-call credentials are not supported
     * @param password ignored because per-call credentials are not supported
     * @return never returns normally
     * @throws SQLFeatureNotSupportedException always, to preserve the tenant pool identity boundary
     */
    @Override
    public @NonNull Connection getConnection(final @NonNull String username, final @NonNull String password)
            throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant-scoped datasource does not allow caller-supplied credentials");
    }

    @Override
    public @NonNull ConnectionBuilder createConnectionBuilder() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant-scoped datasource does not expose raw connection builders");
    }

    @Override
    public @NonNull ShardingKeyBuilder createShardingKeyBuilder() throws SQLException {
        throw new SQLFeatureNotSupportedException(
                "tenant-scoped datasource does not expose raw sharding key builders");
    }

    @Override
    public <T> @NonNull T unwrap(final @NonNull Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) {
            return iface.cast(this);
        }
        throw new SQLException("tenant-scoped datasource does not expose its delegate");
    }

    @Override
    public boolean isWrapperFor(final @NonNull Class<?> iface) {
        return iface.isInstance(this);
    }

    /**
     * Closes the hidden delegate when it owns non-bean tenant resources.
     *
     * <p>ID and schema modes use Spring-managed raw pools, so their delegates normally have nothing
     * to close. Database mode creates one guarded pool per tenant behind the primary datasource; this
     * method lets Spring's inferred destroy callback close those pools without exposing them.
     *
     * @throws Exception when the delegate fails during close
     */
    @Override
    public void close() throws Exception {
        if (delegate instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    /**
     * Applies the signed tenant claim to a freshly borrowed raw connection.
     *
     * <p>If binding fails, the connection is aborted instead of returned normally to the pool because
     * its session state is unknown.
     *
     * @param raw the raw connection returned by the delegate datasource
     * @param tenantClaim signed claim to bind into the PostgreSQL session
     * @return a guarded connection that resets the tenant session binding on close
     * @throws SQLException when tenant binding fails
     */
    private Connection bind(final Connection raw, final String tenantClaim) throws SQLException {
        try {
            applyBinding(raw, tenantClaim);
        } catch (SQLException | RuntimeException ex) {
            abortQuietly(raw);
            throw ex;
        }
        notifyObserver(() -> observer.onBindingSet(poolName));
        return wrapForSessionReset(raw);
    }

    /**
     * Closes a connection while intentionally suppressing close failures.
     *
     * <p>This helper is used only on already-failing paths where preserving the original failure is
     * more useful than replacing it with cleanup noise.
     *
     * @param raw the connection to close
     */
    private static void closeQuietly(final Connection raw) {
        try {
            raw.close();
        } catch (SQLException suppressed) {
            // ignore; we are already failing fast
        }
    }

    /**
     * Aborts a connection and falls back to close if the driver cannot abort it.
     *
     * <p>{@link Connection#abort(Executor)} requires an executor; the direct executor is enough
     * because the caller is already on a cleanup path and no asynchronous scheduling is needed.
     *
     * @param raw the connection whose session state should not be returned to the pool
     */
    private static void abortQuietly(final Connection raw) {
        try {
            raw.abort(DIRECT_EXECUTOR);
        } catch (SQLException suppressed) {
            closeQuietly(raw);
        }
    }

    /**
     * Returns a signed claim for the current tenant or fails before a raw connection is borrowed.
     *
     * <p>No pool connection is touched on missing context, so an unbound borrow cannot leak a usable
     * untenanted session to the caller or churn the pool.
     *
     * @return signed PostgreSQL tenant claim for the current tenant
     * @throws IllegalStateException when no tenant is present in {@link TenantContext}
     */
    private String requireTenantClaimOrFail() {
        return claimSigner.sign(TenantContext.current()
                .map(TenantId::value)
                .orElseThrow(() -> {
                    notifyObserver(() -> observer.onBindingMissing(poolName));
                    return new IllegalStateException("TenantContext not populated — tenant-scoped datasource '"
                            + poolName + "' requires tenant binding");
                }));
    }

    /**
     * Runs an observer callback without letting metrics/alerting failures break the datasource
     * boundary or skip required JDBC cleanup.
     *
     * @param callback observer notification to run
     */
    private static void notifyObserver(final Runnable callback) {
        try {
            callback.run();
        } catch (RuntimeException suppressed) {
            // Observability must not change tenant-binding behavior.
        }
    }

    /**
     * Writes the signed tenant claim into the PostgreSQL session.
     *
     * @param raw the connection whose session setting should be updated
     * @param tenantClaim the signed tenant claim to bind into {@code app.tenant_claim}
     * @throws SQLException when PostgreSQL rejects the session setting update
     */
    private static void applyBinding(final Connection raw, final String tenantClaim) throws SQLException {
        setConfig(raw, tenantClaim);
    }

    /**
     * Stores the signed tenant claim in PostgreSQL's custom session setting.
     *
     * <p>The third {@code set_config} argument is {@code false} so the value is session-scoped
     * rather than transaction-local; this lets RLS see it for the full borrow until close resets it.
     *
     * @param raw the connection whose PostgreSQL session setting should be populated
     * @param value the signed tenant claim
     * @throws SQLException when the setting cannot be written
     */
    private static void setConfig(final Connection raw, final String value)
            throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            stmt.setString(1, TenantSessionDataSourceProxy.TENANT_CLAIM_SETTING);
            stmt.setString(2, value);
            stmt.setBoolean(3, false);
            stmt.execute();
        }
    }

    /**
     * Clears the tenant claim from PostgreSQL's custom session setting.
     *
     * <p>A SQL-level clear is used because the claim lives in the PostgreSQL session state, not in the Java
     * connection wrapper state. The caller is responsible for ensuring this clear cannot be rolled
     * back by an open transaction.
     *
     * @param raw the connection whose PostgreSQL session setting should be cleared
     * @throws SQLException when the setting cannot be cleared
     */
    private static void clearConfig(final Connection raw) throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            stmt.setString(1, TenantSessionDataSourceProxy.TENANT_CLAIM_SETTING);
            stmt.setNull(2, Types.VARCHAR);
            stmt.setBoolean(3, false);
            stmt.execute();
        }
    }

    /**
     * Restores transaction state before clearing the tenant claim.
     *
     * <p>This order is intentional: PostgreSQL session-level {@code set_config(..., false)} calls
     * made inside an open transaction can be undone by a later rollback. If a caller leaves
     * {@code autoCommit=false}, the proxy rolls back first, restores autocommit, and only then
     * clears the tenant claim so Hikari's close-time rollback cannot resurrect the prior binding.
     *
     * @param raw the connection being returned to the pool
     * @throws SQLException when rollback, autocommit restoration, or claim clearing fails
     */
    private static void resetSessionBinding(final Connection raw) throws SQLException {
        if (!raw.getAutoCommit()) {
            raw.rollback();
            raw.setAutoCommit(true);
        }
        clearConfig(raw);
    }

    /**
     * Wraps the raw connection with close/reset and JDBC-wrapper guards.
     *
     * <p>A JDK dynamic proxy is enough here because the public contract is {@link Connection}; the
     * handler keeps all tenant cleanup behavior centralized without depending on a concrete pool
     * implementation class.
     *
     * @param raw the tenant-bound raw connection
     * @return a connection proxy that resets the tenant binding before returning to the pool
     */
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
        private boolean closed;

        /**
         * Creates the invocation handler for one borrowed connection.
         *
         * @param delegate the tenant-bound connection returned by the underlying pool
         * @param poolName the logical pool name used in observer callbacks
         * @param observer receives reset-failure events
         */
        SessionResetHandler(final Connection delegate, final String poolName, final TenantBindingObserver observer) {
            this.delegate = delegate;
            this.poolName = poolName;
            this.observer = observer;
        }

        /**
         * Intercepts connection calls that can affect the tenant-binding guard.
         *
         * <p>{@code close()} is made idempotent and performs session reset before returning the
         * delegate to the pool. JDBC's {@code isWrapperFor}/{@code unwrap} methods are special-cased
         * because they come from {@link java.sql.Wrapper}; without the proxy-first behavior, callers
         * could unwrap to the raw pool connection and bypass this close/reset handler.
         *
         * @param proxy the connection proxy exposed to callers
         * @param method the invoked {@link Connection} method
         * @param args method arguments, or {@code null} for no-argument methods
         * @return the delegated method result, or {@code null} for {@code close()}
         * @throws Throwable when the delegated JDBC method throws
         */
        @Override
        public @Nullable Object invoke(final Object proxy, final Method method, final @Nullable Object[] args)
                throws Throwable {
            final String methodName = method.getName();
            if ("close".equals(methodName) && hasNoArgs(args)) {
                handleClose();
                return null;
            }
            if ("isWrapperFor".equals(methodName) && hasSingleArg(args)) {
                return handleIsWrapperFor(proxy, args);
            }
            if ("unwrap".equals(methodName) && hasSingleArg(args)) {
                return handleUnwrap(proxy, args);
            }
            return invokeDelegate(method, args);
        }

        private static boolean hasNoArgs(final @Nullable Object[] args) {
            return args == null || args.length == 0;
        }

        private static boolean hasSingleArg(final @Nullable Object[] args) {
            return args != null && args.length == 1;
        }

        /**
         * Clears the tenant session binding, then returns the connection to the pool, exactly once.
         *
         * <p>The reset catch MUST cover {@link RuntimeException} as well as {@link SQLException}: in
         * schema mode the delegate is a {@code SchemaResetConnection} proxy that rethrows driver
         * exception causes verbatim, so {@code resetSessionBinding} can throw unchecked. Narrowing the
         * catch back to {@code SQLException} would let that path skip {@code abortQuietly} and
         * {@code closed = true}, orphaning the borrowed connection instead of aborting it (this is the
         * same reason {@code bind} catches {@code SQLException | RuntimeException}). A claim-bearing
         * connection must never be returned to the pool unreset — abort is the only safe disposal when
         * the reset fails. Do not narrow it.
         *
         * @throws SQLException when returning the connection to the pool fails
         */
        private void handleClose() throws SQLException {
            if (closed) {
                return;
            }
            try {
                resetSessionBinding(delegate);
            } catch (SQLException | RuntimeException ex) {
                notifyObserver(() -> observer.onResetFailed(poolName));
                abortQuietly(delegate);
                closed = true;
                return;
            }
            try {
                delegate.close();
            } finally {
                closed = true;
            }
        }

        private static boolean handleIsWrapperFor(final Object proxy, final @Nullable Object[] args) {
            final Class<?> iface = wrapperInterface(args);
            return iface != null && iface.isInstance(proxy);
        }

        private static Object handleUnwrap(final Object proxy, final @Nullable Object[] args) throws SQLException {
            final Class<?> iface = wrapperInterface(args);
            if (iface == null) {
                throw new SQLException(WRAPPER_INTERFACE_REQUIRED);
            }
            if (iface.isInstance(proxy)) {
                return iface.cast(proxy);
            }
            throw new SQLException("tenant-guarded connection does not expose its delegate");
        }

        private static @Nullable Class<?> wrapperInterface(final @Nullable Object[] args) {
            return (Class<?>) Objects.requireNonNull(args, ARGS_REQUIRED)[0];
        }

        private Object invokeDelegate(final Method method, final @Nullable Object[] args) throws Throwable {
            try {
                return method.invoke(delegate, args);
            } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
            }
        }
    }
}
