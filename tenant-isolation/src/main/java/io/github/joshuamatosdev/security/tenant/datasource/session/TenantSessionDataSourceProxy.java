package io.github.joshuamatosdev.security.tenant.datasource.session;

import java.sql.Connection;
import java.sql.ConnectionBuilder;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.ShardingKeyBuilder;
import java.sql.Types;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.OrganizationScope;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingSource;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingObserver;
import io.github.joshuamatosdev.security.tenant.datasource.ResettingConnectionProxy;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.jdbc.datasource.AbstractDataSource;

/**
 * Binds PostgreSQL session variable {@code app.tenant_claim} on every Spring-managed connection
 * borrow so that per-table RLS policies evaluate against the active {@link TenantBindingSource}.
 *
 * <p>The setting is a signed claim, not the tenant authority by itself. PostgreSQL verifies the
 * HMAC with a DB-private secret before RLS trusts it. The returned connection is wrapped so {@link
 * Connection#close()} clears the claim before the connection returns to the pool.
 *
 * <p>When {@code tenant.binding.organization-scope} is {@code optional} or {@code required}, the
 * proxy also binds {@code app.org_claim} — a separately versioned signed claim for the
 * organization dimension of the binding — so organization-aware row policies can subdivide the
 * tenant. Under {@code required}, an ordinary tenant borrow without a bound organization fails
 * closed before a connection is taken; the system-operations tenant is exempt because cross-tenant
 * operational work carries no organization.
 *
 * <p>Fail-closed: if no tenant binding is populated at borrow time, borrowing throws
 * {@link IllegalStateException} before any SQL can run.
 *
 * <p>Why this exists: database-enforced isolation depends on stamping every borrowed connection
 * with a signed tenant claim before application SQL runs.
 */
@SystemTenantBoundary
public final class TenantSessionDataSourceProxy extends AbstractDataSource implements TenantPoolInspection, AutoCloseable {

    private static final String SET_CONFIG_SQL = "SELECT set_config(?, ?, ?)";
    private static final String TENANT_CLAIM_SETTING = "app.tenant_claim";
    private static final String ORGANIZATION_CLAIM_SETTING = "app.org_claim";

    private final DataSource delegate;
    private final String poolName;
    private final TenantClaimSigner claimSigner;
    private final TenantBindingSource bindingSource;
    private final OrganizationScope organizationScope;
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
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantBindingSource bindingSource) {
        this(delegate, poolName, claimSigner, bindingSource, OrganizationScope.OFF,
                TenantBindingObserver.NOOP, TenantPoolInspection.NONE);
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
            final TenantBindingSource bindingSource,
            final TenantPoolInspection poolInspection) {
        this(delegate, poolName, claimSigner, bindingSource, OrganizationScope.OFF,
                TenantBindingObserver.NOOP, poolInspection);
    }

    /**
     * Creates a tenant-binding datasource proxy with an organization scope and pool inspection.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant and organization claims verified inside RLS policies
     * @param organizationScope how the borrow treats the organization dimension of the binding
     * @param poolInspection exposes read-only pool state for trusted infrastructure
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantBindingSource bindingSource,
            final OrganizationScope organizationScope,
            final TenantPoolInspection poolInspection) {
        this(delegate, poolName, claimSigner, bindingSource,
                organizationScope, TenantBindingObserver.NOOP, poolInspection);
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
            final TenantBindingSource bindingSource,
            final TenantBindingObserver observer) {
        this(delegate, poolName, claimSigner, bindingSource,
                OrganizationScope.OFF, observer, TenantPoolInspection.NONE);
    }

    /**
     * Creates a tenant-binding datasource proxy with explicit observability and inspection callbacks.
     *
     * @param delegate the datasource that owns the physical or pooled JDBC connections
     * @param poolName the metric/logging name used when reporting binding events
     * @param claimSigner signs the tenant and organization claims verified inside RLS policies
     * @param organizationScope how the borrow treats the organization dimension of the binding
     * @param observer receives binding, missing-binding, and reset-failure events
     * @param poolInspection exposes read-only pool state for trusted infrastructure
     */
    public TenantSessionDataSourceProxy(
            final DataSource delegate,
            final String poolName,
            final TenantClaimSigner claimSigner,
            final TenantBindingSource bindingSource,
            final OrganizationScope organizationScope,
            final TenantBindingObserver observer,
            final TenantPoolInspection poolInspection) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.poolName = RequiredText.require(poolName, "poolName");
        this.claimSigner = Objects.requireNonNull(claimSigner, "claimSigner");
        this.bindingSource = Objects.requireNonNull(bindingSource, "bindingSource");
        this.organizationScope = Objects.requireNonNull(organizationScope, "organizationScope");
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
     * Signs the current tenant claim (and, per the configured {@link OrganizationScope}, the
     * organization claim), borrows a connection, and immediately binds the claims to the PostgreSQL
     * session.
     *
     * <p>Fail-closed behavior is enforced before the caller receives the connection: if no
     * a tenant binding exists — or the scope is {@code required} and an ordinary tenant borrow
     * has no organization — no connection is borrowed and no SQL can run.
     *
     * @return a guarded connection whose {@link Connection#close()} clears the bound claims
     * @throws SQLException when borrowing or binding, the underlying connection fails
     */
    @Override
    public @NonNull Connection getConnection() throws SQLException {
        final TenantId tenant = requireTenantOrFail();
        final String tenantClaim = claimSigner.sign(tenant.value());
        final String organizationClaim = organizationClaimFor(tenant);
        return bind(delegate.getConnection(), tenantClaim, organizationClaim);
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
     * Applies the signed claims to a freshly borrowed raw connection.
     *
     * <p>If binding fails, the connection is aborted instead of returned normally to the pool because
     * its session state is unknown.
     *
     * @param raw the raw connection returned by the delegate datasource
     * @param tenantClaim signed tenant claim to bind into the PostgreSQL session
     * @param organizationClaim signed organization claim, or {@code null} when this borrow binds none
     * @return a guarded connection that resets the session binding on close
     * @throws SQLException when claim binding fails
     */
    private Connection bind(
            final Connection raw, final String tenantClaim, final @Nullable String organizationClaim)
            throws SQLException {
        try {
            applyBinding(raw, tenantClaim, organizationClaim);
        } catch (SQLException | RuntimeException ex) {
            ResettingConnectionProxy.abortQuietly(raw);
            throw ex;
        }
        notifyObserver(() -> observer.onBindingSet(poolName));
        return wrapForSessionReset(raw);
    }

    /**
     * Returns the current tenant or fails before a raw connection is borrowed.
     *
     * <p>No pool connection is touched on missing context, so an unbound borrow cannot leak a usable
     * untenanted session to the caller or churn the pool.
     *
     * @return the tenant bound to the calling thread
     * @throws IllegalStateException when no tenant is present in the binding source
     */
    private TenantId requireTenantOrFail() {
        return bindingSource.current()
                .orElseThrow(() -> {
                    notifyObserver(() -> observer.onBindingMissing(poolName));
                    return new IllegalStateException("TenantContext not populated — tenant-scoped datasource '"
                            + poolName + "' requires tenant binding");
                });
    }

    /**
     * Returns the signed organization claim this borrow should bind, or fails closed.
     *
     * <p>{@link OrganizationScope#OFF} never binds one. The system-operations tenant never carries
     * one — cross-tenant operational work is not organization-scoped — so the {@code required}
     * check applies to ordinary tenants only.
     *
     * @param tenant the tenant bound to the calling thread
     * @return signed organization claim, or {@code null} when this borrow binds none
     * @throws IllegalStateException when the scope is {@code required} and an ordinary tenant borrow
     *     has no bound organization
     */
    private @Nullable String organizationClaimFor(final TenantId tenant) {
        if (organizationScope == OrganizationScope.OFF || TenantIds.SYSTEM_OPS.equals(tenant)) {
            return null;
        }
        final Optional<String> claim = bindingSource.currentOrganization()
                .map(organization -> claimSigner.signOrganization(organization.value()));
        if (claim.isEmpty() && organizationScope == OrganizationScope.REQUIRED) {
            notifyObserver(() -> observer.onOrganizationBindingMissing(poolName));
            throw new IllegalStateException("TenantContext organization not populated — tenant-scoped"
                    + " datasource '" + poolName + "' requires organization binding"
                    + " (tenant.binding.organization-scope=required)");
        }
        return claim.orElse(null);
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
     * Writes the signed claims into the PostgreSQL session.
     *
     * @param raw the connection whose session settings should be updated
     * @param tenantClaim the signed tenant claim to bind into {@code app.tenant_claim}
     * @param organizationClaim signed organization claim for {@code app.org_claim}, or {@code null}
     * @throws SQLException when PostgreSQL rejects a session setting update
     */
    private static void applyBinding(
            final Connection raw, final String tenantClaim, final @Nullable String organizationClaim)
            throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            setConfig(stmt, TENANT_CLAIM_SETTING, tenantClaim);
            setConfig(stmt, ORGANIZATION_CLAIM_SETTING, organizationClaim);
        }
    }

    /**
     * Stores a signed claim in a PostgreSQL custom session setting.
     *
     * <p>The third {@code set_config} argument is {@code false} so the value is session-scoped
     * rather than transaction-local; this lets RLS see it for the full borrow until close resets it.
     *
     * @param stmt prepared {@code set_config} statement
     * @param setting the custom session setting name
     * @param value the signed claim, or {@code null} to clear stale state before the borrow
     * @throws SQLException when the setting cannot be written
     */
    private static void setConfig(
            final PreparedStatement stmt, final String setting, final @Nullable String value)
            throws SQLException {
        stmt.setString(1, setting);
        if (value == null) {
            stmt.setNull(2, Types.VARCHAR);
        } else {
            stmt.setString(2, value);
        }
        stmt.setBoolean(3, false);
        stmt.execute();
    }

    /**
     * Clears the bound claims from PostgreSQL's custom session settings.
     *
     * <p>A SQL-level clear is used because the claims live in the PostgreSQL session state, not in the
     * Java connection wrapper state. The caller is responsible for ensuring this clear cannot be
     * rolled back by an open transaction.
     *
     * @param raw the connection whose PostgreSQL session settings should be cleared
     * @throws SQLException when a setting cannot be cleared
     */
    private static void clearConfig(final Connection raw) throws SQLException {
        try (PreparedStatement stmt = raw.prepareStatement(SET_CONFIG_SQL)) {
            clearSetting(stmt, TENANT_CLAIM_SETTING);
            clearSetting(stmt, ORGANIZATION_CLAIM_SETTING);
        }
    }

    /**
     * Clears one custom session setting through the shared {@code set_config} statement.
     *
     * @param stmt prepared {@code set_config} statement
     * @param setting the custom session setting name to clear
     * @throws SQLException when the setting cannot be cleared
     */
    private static void clearSetting(final PreparedStatement stmt, final String setting)
            throws SQLException {
        stmt.setString(1, setting);
        stmt.setNull(2, Types.VARCHAR);
        stmt.setBoolean(3, false);
        stmt.execute();
    }

    /**
     * Restores transaction state before clearing the bound claims.
     *
     * <p>This order is intentional: PostgreSQL session-level {@code set_config(..., false)} calls
     * made inside an open transaction can be undone by a later rollback. If a caller leaves
     * {@code autoCommit=false}, the proxy rolls back first, restores autocommit, and only then
     * clears the claims so Hikari's close-time rollback cannot resurrect the prior binding.
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
     * @return a connection proxy that resets the session binding before returning to the pool
     */
    private Connection wrapForSessionReset(final Connection raw) {
        return ResettingConnectionProxy.wrap(
                raw,
                "tenant-guarded connection is closed",
                "tenant-guarded connection does not expose its delegate",
                this::closeTenantSession);
    }

    /**
     * Clears the session binding, then returns the connection to the pool.
     *
     * <p>The reset catch MUST cover {@link RuntimeException} as well as {@link SQLException}: schema
     * mode wraps the delegate and can surface driver exception causes verbatim. A claim-bearing
     * connection must never be returned to the pool unreset; abort is the only safe disposal when
     * reset fails.
     *
     * @param raw the tenant-bound connection returned by the underlying pool
     * @throws SQLException when returning the connection to the pool fails
     */
    private void closeTenantSession(final Connection raw) throws SQLException {
        try {
            resetSessionBinding(raw);
        } catch (SQLException | RuntimeException ex) {
            notifyObserver(() -> observer.onResetFailed(poolName));
            ResettingConnectionProxy.abortQuietly(raw);
            return;
        }
        try {
            raw.close();
        } catch (SQLException | RuntimeException ex) {
            ResettingConnectionProxy.abortQuietly(raw);
            throw ex;
        }
    }
}
