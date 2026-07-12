package io.github.joshuamatosdev.security.tenant;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Pure PostgreSQL connection rules shared by runtime and per-tenant pool configuration.
 */
@SystemTenantBoundary
public final class PostgresConnectionPolicy {

    private static final Pattern JDBC_URL = Pattern.compile("jdbc:[A-Za-z][A-Za-z0-9._-]*:\\S+");
    private static final String POSTGRES_JDBC_URL_PREFIX = "jdbc:postgresql:";
    private static final String TENANT_DATABASE_POOL_PREFIX = "tenant-db-";
    private static final Set<String> FORBIDDEN_TENANT_USERNAMES =
            Set.of("postgres", "app_superuser", "tenant_bypass", "tenant_ops_user", "application_owner");

    private PostgresConnectionPolicy() {}

    /** Returns a required-text violation without throwing. */
    public static Optional<String> requiredTextViolation(final String value) {
        return value == null ? Optional.of("must not be blank") : RequiredText.violation(value);
    }

    /** Returns whether the value has JDBC URL syntax. */
    public static boolean isJdbcUrl(final String value) {
        return value != null && JDBC_URL.matcher(value).matches();
    }

    /** Returns whether the value selects the PostgreSQL JDBC driver. */
    public static boolean isPostgresJdbcUrl(final String value) {
        return value != null && value.startsWith(POSTGRES_JDBC_URL_PREFIX);
    }

    /** Returns the first unsafe PostgreSQL JDBC parameter, if present. */
    public static Optional<String> unsafeJdbcParameter(final String value) {
        return PostgresJdbcUrls.firstUnsafeQueryParameter(value);
    }

    /** Returns whether a username is reserved for privileged or system operations. */
    public static boolean isForbiddenTenantUsername(final String value) {
        return value != null && FORBIDDEN_TENANT_USERNAMES.contains(value.toLowerCase(Locale.ROOT));
    }

    /** Derives the stable default pool name for a tenant. */
    public static String defaultTenantPoolName(final TenantId tenantId) {
        return TENANT_DATABASE_POOL_PREFIX + tenantId;
    }
}
