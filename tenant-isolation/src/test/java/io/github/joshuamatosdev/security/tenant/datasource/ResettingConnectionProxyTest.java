package io.github.joshuamatosdev.security.tenant.datasource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Proxy;
import java.sql.Connection;
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
}
