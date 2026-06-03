package io.github.joshuamatosdev.security.tenant.datasource.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.zaxxer.hikari.HikariDataSource;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.TenantBindingObserver;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolInspection;
import io.github.joshuamatosdev.security.tenant.datasource.pool.TenantPoolSnapshot;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Types;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.jdbc.datasource.DelegatingDataSource;

class TenantSessionDataSourceProxyTest {

    private static final String DELEGATE_EXPOSURE_MESSAGE = "does not expose its delegate";
    private static final String POOL_NAME = "tenant";
    private static final String RUNTIME_POOL_NAME = "tenant-runtime";
    private static final String TENANT_CLAIM_SETTING = "app.tenant_claim";
    private static final String WRAPPER_INTERFACE_MESSAGE = "wrapper interface";
    private static final TenantClaimSigner CLAIM_SIGNER = new TenantClaimSigner(
            TenantTestConstants.CLAIM_SECRET, Duration.ofMinutes(30), Clock.systemUTC());

    @AfterEach
    void clearTenantContext() {
        TenantContext.clear();
    }

    @Test
    void rejectsCallerSuppliedCredentials() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);

        assertThatThrownBy(() -> proxy.getConnection(
                        TenantTestConstants.POSTGRES_USERNAME,
                        TenantTestConstants.POSTGRES_PASSWORD))
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining(TenantTestConstants.CALLER_SUPPLIED_CREDENTIALS_MESSAGE);

        verify(delegate, never()).getConnection(anyString(), anyString());
    }

    @Test
    void doesNotExposeTheDelegateDataSource() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        final Class<? extends DataSource> delegateClass = delegate.getClass();
        when(delegate.isWrapperFor(delegateClass)).thenReturn(true);

        assertThat(proxy).isNotInstanceOf(DelegatingDataSource.class);
        assertThat(proxy.isWrapperFor(DataSource.class)).isTrue();
        assertThat(proxy.unwrap(DataSource.class)).isSameAs(proxy);
        assertThat(proxy.isWrapperFor(delegateClass)).isFalse();
        assertThatThrownBy(() -> proxy.unwrap(delegateClass))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining(DELEGATE_EXPOSURE_MESSAGE);
        assertThat(proxy.isWrapperFor(HikariDataSource.class)).isFalse();
        assertThatThrownBy(() -> proxy.unwrap(HikariDataSource.class))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining(DELEGATE_EXPOSURE_MESSAGE);
        assertThatThrownBy(proxy::createConnectionBuilder)
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining("connection builders");
        assertThatThrownBy(proxy::createShardingKeyBuilder)
                .isInstanceOf(SQLFeatureNotSupportedException.class)
                .hasMessageContaining("sharding key builders");

        verify(delegate, never()).isWrapperFor(delegateClass);
        verify(delegate, never()).unwrap(delegateClass);
        verify(delegate, never()).createConnectionBuilder();
        verify(delegate, never()).createShardingKeyBuilder();
    }

    @Test
    void unwrapDataSourceToPoolInspectionExposesOnlyReadOnlySnapshots() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantPoolSnapshot snapshot = new TenantPoolSnapshot(RUNTIME_POOL_NAME, 1, 2, 3, 4, 0, 10);
        final TenantSessionDataSourceProxy proxy = new TenantSessionDataSourceProxy(
                delegate,
                POOL_NAME,
                CLAIM_SIGNER,
                () -> List.of(snapshot));

        assertThat(proxy.isWrapperFor(TenantPoolInspection.class)).isTrue();
        final TenantPoolInspection inspection = proxy.unwrap(TenantPoolInspection.class);

        assertThat(inspection).isSameAs(proxy);
        assertThat(inspection.snapshots()).containsExactly(snapshot);
    }

    @Test
    void abortsConnectionWhenBindingFails() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        final SQLException bindingFailure = new SQLException("binding failed");
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenThrow(bindingFailure);

        assertThatThrownBy(() -> supplyAsAcme(proxy::getConnection)).isSameAs(bindingFailure);

        verify(raw).abort(any());
    }

    @Test
    void missingTenantContextFailsBeforeBorrowingConnection() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final TenantSessionDataSourceProxy proxy = new TenantSessionDataSourceProxy(
                delegate,
                POOL_NAME,
                CLAIM_SIGNER,
                observerThrowingOn(ObserverFailure.BINDING_MISSING));

        assertThatThrownBy(proxy::getConnection)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(TenantTestConstants.TENANT_CONTEXT_NOT_POPULATED_MESSAGE);

        verify(delegate, never()).getConnection();
    }

    @Test
    void signerFailureHappensBeforeBorrowingConnection() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Clock failingClock = mock(Clock.class);
        final TenantClaimSigner failingSigner = new TenantClaimSigner(
                TenantTestConstants.CLAIM_SECRET,
                Duration.ofMinutes(30),
                failingClock);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, failingSigner);
        when(failingClock.instant()).thenThrow(new IllegalStateException("clock failed"));

        assertThatThrownBy(() -> supplyAsAcme(proxy::getConnection))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("clock failed");

        verify(delegate, never()).getConnection();
    }

    @Test
    void observerFailureAfterBindingDoesNotLeakTheBorrowedConnection() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final PreparedStatement bindingStatement = mock(PreparedStatement.class);
        final PreparedStatement resetStatement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy = new TenantSessionDataSourceProxy(
                delegate,
                POOL_NAME,
                CLAIM_SIGNER,
                observerThrowingOn(ObserverFailure.BINDING_SET));
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(bindingStatement, resetStatement);
        when(raw.getAutoCommit()).thenReturn(true);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);
        wrapped.close();

        verify(raw).close();
    }

    @Test
    void observerFailureOnResetFailureStillAbortsTheConnection() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final PreparedStatement bindingStatement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy = new TenantSessionDataSourceProxy(
                delegate,
                POOL_NAME,
                CLAIM_SIGNER,
                observerThrowingOn(ObserverFailure.RESET_FAILED));
        final SQLException resetFailure = new SQLException("reset failed");
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(bindingStatement).thenThrow(resetFailure);
        when(raw.getAutoCommit()).thenReturn(true);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);

        assertThatCode(wrapped::close).doesNotThrowAnyException();
        verify(raw).abort(any());
    }

    @Test
    void clearsBindingAfterRollingBackCallerLeftTransaction() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final PreparedStatement bindingStatement = mock(PreparedStatement.class);
        final PreparedStatement resetStatement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(bindingStatement, resetStatement);
        when(raw.getAutoCommit()).thenReturn(false);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);
        wrapped.close();

        final InOrder inOrder = inOrder(raw, bindingStatement, resetStatement);
        inOrder.verify(raw).prepareStatement(anyString());
        inOrder.verify(bindingStatement).execute();
        inOrder.verify(bindingStatement).close();
        inOrder.verify(raw).getAutoCommit();
        inOrder.verify(raw).rollback();
        inOrder.verify(raw).setAutoCommit(true);
        inOrder.verify(raw).prepareStatement(anyString());
        inOrder.verify(resetStatement).setString(1, TENANT_CLAIM_SETTING);
        inOrder.verify(resetStatement).setNull(2, Types.VARCHAR);
        inOrder.verify(resetStatement).setBoolean(3, false);
        inOrder.verify(resetStatement).execute();
        inOrder.verify(resetStatement).close();
        inOrder.verify(raw).close();
    }

    @Test
    void unwrapConnectionReturnsTheTenantGuardedWrapper() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final PreparedStatement statement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(statement);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);
        final Connection unwrapped = wrapped.unwrap(Connection.class);

        assertThat(wrapped.isWrapperFor(Connection.class)).isTrue();
        assertThat(unwrapped).isSameAs(wrapped);
    }

    @Test
    void nullConnectionWrapperInterfaceDoesNotReachTheRawDelegate() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final Connection raw = mock(Connection.class);
        final PreparedStatement statement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(statement);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);

        assertThat(wrapped.isWrapperFor(null)).isFalse();
        assertThatThrownBy(() -> wrapped.unwrap(null))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining(WRAPPER_INTERFACE_MESSAGE);
        verify(raw, never()).isWrapperFor(null);
        verify(raw, never()).unwrap(null);
    }

    @Test
    void unwrapConnectionDoesNotExposeTheRawDelegate() throws Exception {
        final DataSource delegate = mock(DataSource.class);
        final VendorConnection raw = mock(VendorConnection.class);
        final PreparedStatement statement = mock(PreparedStatement.class);
        final TenantSessionDataSourceProxy proxy =
                new TenantSessionDataSourceProxy(delegate, POOL_NAME, CLAIM_SIGNER);
        when(delegate.getConnection()).thenReturn(raw);
        when(raw.prepareStatement(anyString())).thenReturn(statement);
        when(raw.isWrapperFor(VendorConnection.class)).thenReturn(true);
        when(raw.unwrap(VendorConnection.class)).thenReturn(raw);

        final Connection wrapped = supplyAsAcme(proxy::getConnection);

        assertThat(wrapped.isWrapperFor(VendorConnection.class)).isFalse();
        assertThatThrownBy(() -> wrapped.unwrap(VendorConnection.class))
                .isInstanceOf(SQLException.class)
                .hasMessageContaining(DELEGATE_EXPOSURE_MESSAGE);
        verify(raw, never()).isWrapperFor(VendorConnection.class);
        verify(raw, never()).unwrap(VendorConnection.class);
    }

    private static Connection supplyAsAcme(final SqlConnectionSupplier work) throws SQLException {
        final AtomicReference<Connection> result = new AtomicReference<>();
        final AtomicReference<SQLException> failure = new AtomicReference<>();
        TenantContext.runAs(TenantIds.ACME, () -> {
            try {
                result.set(work.get());
            } catch (final SQLException exception) {
                failure.set(exception);
            }
        });
        final SQLException exception = failure.get();
        if (exception != null) {
            throw exception;
        }
        return result.get();
    }

    private static TenantBindingObserver observerThrowingOn(final ObserverFailure failure) {
        return new TenantBindingObserver() {
            @Override
            public void onBindingSet(final String poolName) {
                throwIf(ObserverFailure.BINDING_SET, failure);
            }

            @Override
            public void onBindingMissing(final String poolName) {
                throwIf(ObserverFailure.BINDING_MISSING, failure);
            }

            @Override
            public void onResetFailed(final String poolName) {
                throwIf(ObserverFailure.RESET_FAILED, failure);
            }
        };
    }

    private static void throwIf(final ObserverFailure callback, final ObserverFailure failure) {
        if (callback == failure) {
            throw new IllegalStateException("observer failed");
        }
    }

    private enum ObserverFailure {
        BINDING_SET,
        BINDING_MISSING,
        RESET_FAILED
    }

    @FunctionalInterface
    private interface SqlConnectionSupplier {
        Connection get() throws SQLException;
    }

    private interface VendorConnection extends Connection {}
}
