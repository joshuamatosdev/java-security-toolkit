package io.github.joshuamatosdev.security.tenant.datasource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ResettingConnectionProxyTest {

    @Test
    void closeActionRunsOnceAndClosedConnectionRejectsFurtherJdbcCalls() throws SQLException {
        final AtomicInteger closeCalls = new AtomicInteger();
        final Connection raw = rawConnection();
        final Connection wrapped = ResettingConnectionProxy.wrap(
                raw,
                "guarded connection is closed",
                "guarded connection does not expose its delegate",
                ignored -> closeCalls.incrementAndGet());

        wrapped.close();
        wrapped.close();

        assertThat(closeCalls).hasValue(1);
        assertThat(wrapped.isClosed()).isTrue();
        assertThatThrownBy(wrapped::createStatement)
                .isInstanceOf(SQLException.class)
                .hasMessage("guarded connection is closed");
    }

    @Test
    void unwrapReturnsOnlyTheGuardedProxy() throws SQLException {
        final Connection raw = rawConnection();
        final Connection wrapped = ResettingConnectionProxy.wrap(
                raw,
                "guarded connection is closed",
                "guarded connection does not expose its delegate",
                Connection::close);

        assertThat(wrapped.isWrapperFor(Connection.class)).isTrue();
        assertThat(wrapped.unwrap(Connection.class)).isSameAs(wrapped);
        assertThatThrownBy(() -> wrapped.unwrap(Statement.class))
                .isInstanceOf(SQLException.class)
                .hasMessage("guarded connection does not expose its delegate");
    }

    @Test
    void childJdbcObjectsReturnOnlyGuardedParentObjects() throws SQLException {
        final Connection raw = mock(Connection.class);
        final VendorStatement rawStatement = mock(VendorStatement.class);
        final ResultSet rawResultSet = mock(ResultSet.class);
        final DatabaseMetaData rawMetadata = mock(DatabaseMetaData.class);
        when(raw.createStatement()).thenReturn(rawStatement);
        when(rawStatement.getConnection()).thenReturn(raw);
        when(rawStatement.executeQuery("SELECT 1")).thenReturn(rawResultSet);
        when(rawResultSet.getStatement()).thenReturn(rawStatement);
        when(raw.getMetaData()).thenReturn(rawMetadata);
        when(rawMetadata.getConnection()).thenReturn(raw);
        final Connection wrapped = ResettingConnectionProxy.wrap(
                raw,
                "guarded connection is closed",
                "guarded connection does not expose its delegate",
                Connection::close);

        final Statement guardedStatement = wrapped.createStatement();
        final ResultSet guardedResultSet = guardedStatement.executeQuery("SELECT 1");
        final DatabaseMetaData guardedMetadata = wrapped.getMetaData();

        assertThat(guardedStatement).isNotSameAs(rawStatement);
        assertThat(guardedStatement.getConnection()).isSameAs(wrapped);
        assertThat(guardedStatement.isWrapperFor(Statement.class)).isTrue();
        assertThat(guardedStatement.unwrap(Statement.class)).isSameAs(guardedStatement);
        assertThat(guardedStatement.isWrapperFor(VendorStatement.class)).isFalse();
        assertThatThrownBy(() -> guardedStatement.unwrap(VendorStatement.class))
                .isInstanceOf(SQLException.class)
                .hasMessage("guarded connection does not expose its delegate");
        assertThat(guardedResultSet).isNotSameAs(rawResultSet);
        assertThat(guardedResultSet.getStatement()).isSameAs(guardedStatement);
        assertThat(guardedMetadata).isNotSameAs(rawMetadata);
        assertThat(guardedMetadata.getConnection()).isSameAs(wrapped);
    }

    @Test
    void closingThroughAStatementBackReferenceRunsTheGuardedCloseAction() throws SQLException {
        final AtomicInteger closeCalls = new AtomicInteger();
        final Connection raw = mock(Connection.class);
        final Statement rawStatement = mock(Statement.class);
        when(raw.createStatement()).thenReturn(rawStatement);
        when(rawStatement.getConnection()).thenReturn(raw);
        final Connection wrapped = ResettingConnectionProxy.wrap(
                raw,
                "guarded connection is closed",
                "guarded connection does not expose its delegate",
                ignored -> closeCalls.incrementAndGet());

        wrapped.createStatement().getConnection().close();

        assertThat(closeCalls).hasValue(1);
        assertThat(wrapped.isClosed()).isTrue();
    }

    private static Connection rawConnection() {
        return (Connection) Proxy.newProxyInstance(
                ResettingConnectionProxyTest.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "close" -> null;
                    case "isClosed" -> false;
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(final Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        if (type == int.class) {
            return 0;
        }
        if (type == long.class) {
            return 0L;
        }
        return null;
    }

    private interface VendorStatement extends Statement {}
}
