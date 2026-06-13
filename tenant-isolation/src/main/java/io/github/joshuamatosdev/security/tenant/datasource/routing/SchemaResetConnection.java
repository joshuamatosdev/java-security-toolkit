package io.github.joshuamatosdev.security.tenant.datasource.routing;

import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.SQLException;
import io.github.joshuamatosdev.security.tenant.datasource.ResettingConnectionProxy;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Connection proxy that restores the prior schema before returning a borrowed connection.
 *
 * <p>Why this exists: tenant placement routing is the boundary that chooses the physical schema or
 * database, so it must be explicit and auditable.
 */
final class SchemaResetConnection {

    private SchemaResetConnection() {}

    static @NonNull Connection wrap(final Connection raw, final @Nullable String priorSchema) {
        return ResettingConnectionProxy.wrap(
                raw,
                "tenant schema connection is closed",
                "tenant schema connection does not expose its delegate",
                connection -> closeOnce(connection, priorSchema));
    }

    static void abortQuietly(final Connection raw) {
        ResettingConnectionProxy.abortQuietly(raw);
    }

    /**
     * Restores the prior schema and closes the raw connection, exactly once.
     *
     * <p>The catch MUST cover {@link RuntimeException} as well as {@link SQLException}: this proxy's
     * rethrows the cause of an {@link InvocationTargetException} verbatim, so a driver
     * can surface unchecked exceptions from {@code rollback}/{@code setAutoCommit}/{@code setSchema}
     * or {@code close}. Narrowing the catch back to {@code SQLException} would skip
     * {@link #abortQuietly(Connection)} on that path and orphan the raw connection with the prior
     * schema unrestored. Do not narrow it.
     *
     * @throws SQLException when the reset or close fails; the connection is aborted first
     */
    private static void closeOnce(final Connection raw, final @Nullable String priorSchema) throws SQLException {
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
