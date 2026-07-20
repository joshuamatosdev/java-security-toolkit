package io.github.joshuamatosdev.security.tenant.datasource;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.concurrent.Executor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * JDBC connection proxy that centralizes close-time reset and prevents child JDBC objects from
 * exposing the underlying pooled connection.
 */
public final class ResettingConnectionProxy {

    private static final String ARGS_REQUIRED = "args";
    private static final String WRAPPER_INTERFACE_REQUIRED = "wrapper interface must not be null";
    private static final Executor DIRECT_EXECUTOR = Runnable::run;

    private ResettingConnectionProxy() {}

    public static @NonNull Connection wrap(
            final Connection delegate,
            final String closedMessage,
            final String hiddenDelegateMessage,
            final CloseAction closeAction) {
        return (Connection) Proxy.newProxyInstance(
                ResettingConnectionProxy.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                new Handler(
                        Objects.requireNonNull(delegate, "delegate"),
                        requireMessage(closedMessage, "closedMessage"),
                        requireMessage(hiddenDelegateMessage, "hiddenDelegateMessage"),
                        Objects.requireNonNull(closeAction, "closeAction")));
    }

    public static void abortQuietly(final Connection raw) {
        try {
            raw.abort(DIRECT_EXECUTOR);
        } catch (SQLException | RuntimeException suppressed) {
            try {
                raw.close();
            } catch (SQLException | RuntimeException closeSuppressed) {
                // Preserve the original failure.
            }
        }
    }

    private static String requireMessage(final String value, final String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }

    @FunctionalInterface
    public interface CloseAction {
        void close(Connection delegate) throws SQLException;
    }

    private static final class Handler implements InvocationHandler {
        private final Connection delegate;
        private final String closedMessage;
        private final String hiddenDelegateMessage;
        private final CloseAction closeAction;
        private boolean closed;

        private Handler(
                final Connection delegate,
                final String closedMessage,
                final String hiddenDelegateMessage,
                final CloseAction closeAction) {
            this.delegate = delegate;
            this.closedMessage = closedMessage;
            this.hiddenDelegateMessage = hiddenDelegateMessage;
            this.closeAction = closeAction;
        }

        @Override
        public @Nullable Object invoke(final Object proxy, final Method method, final @Nullable Object[] args)
                throws Throwable {
            final String methodName = method.getName();
            if ("close".equals(methodName) && method.getParameterCount() == 0) {
                closeOnce();
                return null;
            }
            if ("isClosed".equals(methodName) && method.getParameterCount() == 0) {
                return closed || Boolean.TRUE.equals(invokeDelegate(method, args));
            }
            if (closed && method.getDeclaringClass() != Object.class) {
                throw new SQLException(closedMessage);
            }
            if ("isWrapperFor".equals(methodName) && method.getParameterCount() == 1) {
                final Class<?> iface = wrapperInterface(args);
                return iface != null && iface.isInstance(proxy);
            }
            if ("unwrap".equals(methodName) && method.getParameterCount() == 1) {
                return unwrapProxy(proxy, wrapperInterface(args));
            }
            return guardJdbcObject(
                    (Connection) proxy,
                    null,
                    invokeDelegate(method, args),
                    hiddenDelegateMessage);
        }

        private void closeOnce() throws SQLException {
            if (closed) {
                return;
            }
            try {
                closeAction.close(delegate);
            } finally {
                closed = true;
            }
        }

        private Object unwrapProxy(final Object proxy, final @Nullable Class<?> iface) throws SQLException {
            if (iface == null) {
                throw new SQLException(WRAPPER_INTERFACE_REQUIRED);
            }
            if (iface.isInstance(proxy)) {
                return iface.cast(proxy);
            }
            throw new SQLException(hiddenDelegateMessage);
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

    private static @Nullable Object guardJdbcObject(
            final Connection guardedConnection,
            final @Nullable Statement guardedStatement,
            final @Nullable Object value,
            final String hiddenDelegateMessage) {
        if (value instanceof CallableStatement callableStatement) {
            return childProxy(
                    CallableStatement.class,
                    callableStatement,
                    guardedConnection,
                    null,
                    hiddenDelegateMessage);
        }
        if (value instanceof PreparedStatement preparedStatement) {
            return childProxy(
                    PreparedStatement.class,
                    preparedStatement,
                    guardedConnection,
                    null,
                    hiddenDelegateMessage);
        }
        if (value instanceof Statement statement) {
            return childProxy(
                    Statement.class,
                    statement,
                    guardedConnection,
                    null,
                    hiddenDelegateMessage);
        }
        if (value instanceof ResultSet resultSet) {
            return childProxy(
                    ResultSet.class,
                    resultSet,
                    guardedConnection,
                    guardedStatement,
                    hiddenDelegateMessage);
        }
        if (value instanceof DatabaseMetaData metadata) {
            return childProxy(
                    DatabaseMetaData.class,
                    metadata,
                    guardedConnection,
                    null,
                    hiddenDelegateMessage);
        }
        return value;
    }

    private static Object childProxy(
            final Class<?> jdbcInterface,
            final Object delegate,
            final Connection guardedConnection,
            final @Nullable Statement guardedStatement,
            final String hiddenDelegateMessage) {
        return Proxy.newProxyInstance(
                ResettingConnectionProxy.class.getClassLoader(),
                new Class<?>[] {jdbcInterface},
                new JdbcChildHandler(
                        delegate,
                        guardedConnection,
                        guardedStatement,
                        hiddenDelegateMessage));
    }

    private static final class JdbcChildHandler implements InvocationHandler {
        private final Object delegate;
        private final Connection guardedConnection;
        private final @Nullable Statement guardedStatement;
        private final String hiddenDelegateMessage;

        private JdbcChildHandler(
                final Object delegate,
                final Connection guardedConnection,
                final @Nullable Statement guardedStatement,
                final String hiddenDelegateMessage) {
            this.delegate = delegate;
            this.guardedConnection = guardedConnection;
            this.guardedStatement = guardedStatement;
            this.hiddenDelegateMessage = hiddenDelegateMessage;
        }

        @Override
        public @Nullable Object invoke(final Object proxy, final Method method, final @Nullable Object[] args)
                throws Throwable {
            final String methodName = method.getName();
            if ("getConnection".equals(methodName)
                    && method.getParameterCount() == 0
                    && Connection.class.isAssignableFrom(method.getReturnType())) {
                return guardedConnection;
            }
            if ("getStatement".equals(methodName)
                    && method.getParameterCount() == 0
                    && guardedStatement != null) {
                return guardedStatement;
            }
            if ("isWrapperFor".equals(methodName) && method.getParameterCount() == 1) {
                final Class<?> iface = wrapperInterface(args);
                return iface != null && iface.isInstance(proxy);
            }
            if ("unwrap".equals(methodName) && method.getParameterCount() == 1) {
                return unwrapProxy(proxy, wrapperInterface(args));
            }
            final Object result = invokeDelegate(method, args);
            final Statement resultSetParent = proxy instanceof Statement statement ? statement : null;
            return guardJdbcObject(
                    guardedConnection,
                    resultSetParent,
                    result,
                    hiddenDelegateMessage);
        }

        private Object unwrapProxy(final Object proxy, final @Nullable Class<?> iface) throws SQLException {
            if (iface == null) {
                throw new SQLException(WRAPPER_INTERFACE_REQUIRED);
            }
            if (iface.isInstance(proxy)) {
                return iface.cast(proxy);
            }
            throw new SQLException(hiddenDelegateMessage);
        }

        private static @Nullable Class<?> wrapperInterface(final @Nullable Object[] args) {
            return (Class<?>) Objects.requireNonNull(args, ARGS_REQUIRED)[0];
        }

        private @Nullable Object invokeDelegate(final Method method, final @Nullable Object[] args)
                throws Throwable {
            try {
                return method.invoke(delegate, args);
            } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
            }
        }
    }
}
