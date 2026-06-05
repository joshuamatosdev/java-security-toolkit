package io.github.joshuamatosdev.security.tenant.datasource.routing;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Objects;
import java.util.concurrent.Executor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Connection proxy that restores the prior schema before returning a borrowed connection.
 *
 * <p>Why this exists: tenant placement routing is the boundary that chooses the physical schema or
 * database, so it must be explicit and auditable.
 */
final class SchemaResetConnection implements InvocationHandler {

    private static final String ARGS_REQUIRED = "args";
    private static final String WRAPPER_INTERFACE_REQUIRED = "wrapper interface must not be null";
    private static final Executor DIRECT_EXECUTOR = Runnable::run;

    private final Connection raw;
    private final @Nullable String priorSchema;
    private boolean closed;

    private SchemaResetConnection(final Connection raw, final @Nullable String priorSchema) {
        this.raw = Objects.requireNonNull(raw, "raw");
        this.priorSchema = priorSchema;
    }

    static @NonNull Connection wrap(final Connection raw, final @Nullable String priorSchema) {
        return (Connection) Proxy.newProxyInstance(
                SchemaResetConnection.class.getClassLoader(),
                new Class<?>[] {Connection.class},
                new SchemaResetConnection(raw, priorSchema));
    }

    static void abortQuietly(final Connection raw) {
        try {
            raw.abort(DIRECT_EXECUTOR);
        } catch (Exception ignored) {
            try {
                raw.close();
            } catch (Exception closeIgnored) {
                // Preserve the original failure.
            }
        }
    }

    @Override
    public @Nullable Object invoke(final Object proxy, final Method method, final @Nullable Object[] args)
            throws Throwable {
        final String name = method.getName();
        if ("close".equals(name) && method.getParameterCount() == 0) {
            closeOnce();
            return null;
        }
        if ("isClosed".equals(name) && method.getParameterCount() == 0) {
            return closed || Boolean.TRUE.equals(invokeRaw(method, args));
        }
        if (closed && method.getDeclaringClass() != Object.class) {
            throw new SQLException("tenant schema connection is closed");
        }
        if ("isWrapperFor".equals(name) && method.getParameterCount() == 1) {
            final Class<?> iface = wrapperInterface(args);
            return iface != null && iface.isInstance(proxy);
        }
        if ("unwrap".equals(name) && method.getParameterCount() == 1) {
            return unwrapProxy(proxy, wrapperInterface(args));
        }
        return invokeRaw(method, args);
    }

    private @Nullable Object invokeRaw(final Method method, final @Nullable Object[] args) throws Throwable {
        try {
            return method.invoke(raw, args);
        } catch (InvocationTargetException ex) {
            throw ex.getCause();
        }
    }

    private static Object unwrapProxy(final Object proxy, final @Nullable Class<?> iface) throws SQLException {
        if (iface == null) {
            throw new SQLException(WRAPPER_INTERFACE_REQUIRED);
        }
        if (iface.isInstance(proxy)) {
            return iface.cast(proxy);
        }
        throw new SQLException("tenant schema connection does not expose its delegate");
    }

    private static @Nullable Class<?> wrapperInterface(final @Nullable Object[] args) {
        return (Class<?>) Objects.requireNonNull(args, ARGS_REQUIRED)[0];
    }

    /**
     * Restores the prior schema and closes the raw connection, exactly once.
     *
     * <p>The catch MUST cover {@link RuntimeException} as well as {@link SQLException}: this proxy's
     * {@link #invoke} rethrows the cause of an {@link InvocationTargetException} verbatim, so a driver
     * can surface unchecked exceptions from {@code rollback}/{@code setAutoCommit}/{@code setSchema}/
     * {@code close}. Narrowing the catch back to {@code SQLException} would skip
     * {@link #abortQuietly(Connection)} on that path and — because {@link #closed} is already set —
     * permanently orphan the raw connection with the prior schema unrestored. Do not narrow it.
     *
     * @throws SQLException when the reset or close fails; the connection is aborted first
     */
    private void closeOnce() throws SQLException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (!raw.getAutoCommit()) {
                raw.rollback();
                raw.setAutoCommit(true);
            }
            raw.setSchema(priorSchema);
            raw.close();
        } catch (SQLException | RuntimeException ex) {
            abortQuietly(raw);
            throw ex;
        }
    }
}

