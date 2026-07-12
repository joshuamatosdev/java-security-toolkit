package io.github.joshuamatosdev.security.tenant.config;

import io.github.joshuamatosdev.security.shared.RequiredText;
import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.PostgresConnectionPolicy;
import io.github.joshuamatosdev.security.tenant.binding.SystemTenantBoundary;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

@SystemTenantBoundary
final class TenantPlacementValidator {

    static final String DUPLICATE_TENANT_ID_PREFIX = "duplicate tenant id ";

    private static final Pattern POSTGRES_IDENTIFIER =
            Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final Pattern STABLE_POOL_NAME =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}");
    private static final Pattern JAVA_CLASS_NAME =
            Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
    private static final String TENANT_MESSAGE_PREFIX = "tenant '";

    private TenantPlacementValidator() {}

    static <T> Map<String, T> immutableCopy(final Map<String, T> tenants) {
        return tenants == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(tenants));
    }

    static void requireTenantMap(final Map<?, ?> tenants, final String property) {
        if (tenants == null || tenants.isEmpty()) {
            throw new IllegalArgumentException(property + " must contain at least one tenant");
        }
    }

    static TenantId parseTenantId(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "id");
        try {
            return TenantId.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid UUID id: " + value), ex);
        }
    }

    static <T> T requireTenantConfig(final String alias, final T tenant) {
        if (tenant == null) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires placement config"));
        }
        return tenant;
    }

    static String requireSchemaName(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "schema");
        if (!POSTGRES_IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid schema name: " + value));
        }
        return value;
    }

    static String requireNonBlankWithoutEdgeWhitespace(
            final String alias, final String raw, final String property) {
        final String value = requireNonBlank(alias, raw, property);
        RequiredText.violation(value).ifPresent(violation -> {
            throw new IllegalArgumentException(tenantMessage(alias, property + " " + violation));
        });
        return value;
    }

    static String requireTenantPoolUsername(final String alias, final String raw) {
        final String value = requireNonBlankWithoutEdgeWhitespace(alias, raw, "username");
        if (PostgresConnectionPolicy.isForbiddenTenantUsername(value)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "username must not be a privileged or system-ops identity"));
        }
        return value;
    }

    static String requireJdbcUrl(final String alias, final String raw) {
        final String value = requireNonBlank(alias, raw, "jdbc-url");
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "jdbc-url must not contain control characters"));
        }
        if (!PostgresConnectionPolicy.isJdbcUrl(value)) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid jdbc-url: " + value));
        }
        if (!PostgresConnectionPolicy.isPostgresJdbcUrl(value)) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "must be a PostgreSQL jdbc-url: " + value));
        }
        final var unsafeParameter = PostgresConnectionPolicy.unsafeJdbcParameter(value);
        if (unsafeParameter.isPresent()) {
            throw new IllegalArgumentException(
                    tenantMessage(
                            alias,
                            "jdbc-url must not include unsafe JDBC URL query parameter: "
                                    + unsafeParameter.get()));
        }
        return value;
    }

    static void requireOptionalDriverClassName(final String alias, final String raw) {
        requireOptionalNonBlank(alias, raw, "driver-class-name");
        if (raw != null && !JAVA_CLASS_NAME.matcher(raw).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid driver-class-name: " + raw));
        }
    }

    static void requirePoolName(final String alias, final String raw) {
        if (raw == null) {
            return;
        }
        requireOptionalNonBlank(alias, raw, "pool-name");
        if (!STABLE_POOL_NAME.matcher(raw).matches()) {
            throw new IllegalArgumentException(tenantMessage(alias, "has invalid pool-name: " + raw));
        }
    }

    static String databasePoolName(
            final TenantId tenantId,
            final TenantIsolationProperties.DatabaseTenantProperties placement) {
        if (placement.poolName() != null) {
            return placement.poolName();
        }
        return PostgresConnectionPolicy.defaultTenantPoolName(tenantId);
    }

    static void requirePositive(final String alias, final Integer raw, final String property) {
        if (raw != null && raw <= 0) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires positive " + property));
        }
    }

    static void requireNonNegative(final String alias, final Integer raw, final String property) {
        if (raw != null && raw < 0) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires non-negative " + property));
        }
    }

    static void requireMinimumIdleNotAboveMaximum(
            final String alias, final Integer minimumIdle, final Integer maximumPoolSize) {
        if (minimumIdle != null && maximumPoolSize != null && minimumIdle > maximumPoolSize) {
            throw new IllegalArgumentException(
                    tenantMessage(alias, "requires minimum-idle to be less than or equal to maximum-pool-size"));
        }
    }

    private static String requireNonBlank(final String alias, final String raw, final String property) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires " + property));
        }
        return raw;
    }

    private static void requireOptionalNonBlank(final String alias, final String raw, final String property) {
        if (raw != null && raw.isBlank()) {
            throw new IllegalArgumentException(tenantMessage(alias, "requires non-blank " + property));
        }
    }

    private static String tenantMessage(final String alias, final String message) {
        return TENANT_MESSAGE_PREFIX + alias + "' " + message;
    }

}
