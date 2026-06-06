package io.github.joshuamatosdev.security.tenant;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * PostgreSQL JDBC URL guards shared by tenant datasource configuration.
 *
 * <p>Why this exists: pool creation must keep credentials under trusted configuration control
 * instead of accepting user/password fragments, hidden target overrides, TLS trust inputs, driver
 * plugin hooks, driver-behavior downgrades, auth safety downgrades, or session-startup mutations
 * hidden in JDBC URLs.
 */
public final class PostgresJdbcUrls {

    private static final Set<String> UNSAFE_QUERY_PARAMETERS =
            Set.of(
                    "password",
                    "allowencodingchanges",
                    "pgdbname",
                    "pghost",
                    "pgport",
                    "service",
                    "authenticationpluginclassname",
                    "gsslib",
                    "hostrecheckseconds",
                    "gssusedefaultcreds",
                    "jaasapplicationname",
                    "jaaslogin",
                    "kerberosservername",
                    "loadbalancehosts",
                    "socketfactory",
                    "socketfactoryarg",
                    "sslcert",
                    "sslfactory",
                    "sslfactoryarg",
                    "sslhostnameverifier",
                    "sslkey",
                    "sslpassword",
                    "sslpasswordcallback",
                    "sslrootcert",
                    "sspiserviceclass",
                    "currentschema",
                    "options",
                    "replication",
                    "requireauth",
                    "scrammaxiterations",
                    "targetservertype",
                    "usespnego",
                    "user",
                    "username",
                    "xmlfactoryfactory");
    private static final Set<String> SECURE_SSL_MODES =
            Set.of("require", "verify-ca", "verify-full");

    private PostgresJdbcUrls() {}

    /**
     * Detects query parameters that can carry or indirectly source connection credentials, override
     * the visible connection target, replace TLS trust inputs, instantiate pgJDBC plugin classes, or
     * pre-mutate PostgreSQL session state, or downgrade driver query behavior before the tenant
     * datasource boundary binds its guarded claim.
     *
     * @param jdbcUrl PostgreSQL JDBC URL
     * @return true when the query string contains an unsafe credential, target, trust, plugin, or
     *     session parameter
     */
    public static boolean containsCredentialQueryParameter(final String jdbcUrl) {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl must not be null");
        int tokenStart = jdbcUrl.indexOf('?');
        if (tokenStart == -1 || tokenStart == jdbcUrl.length() - 1) {
            return false;
        }
        tokenStart++;
        while (tokenStart < jdbcUrl.length()) {
            final int tokenEnd = nextTokenEnd(jdbcUrl, tokenStart);
            if (tokenEnd > tokenStart && isUnsafeParameter(jdbcUrl, tokenStart, tokenEnd)) {
                return true;
            }
            if (tokenEnd == jdbcUrl.length()) {
                return false;
            }
            tokenStart = tokenEnd + 1;
        }
        return false;
    }

    private static int nextTokenEnd(final String jdbcUrl, final int tokenStart) {
        final int ampersand = jdbcUrl.indexOf('&', tokenStart);
        return ampersand == -1 ? jdbcUrl.length() : ampersand;
    }

    private static String parameterName(final String jdbcUrl, final int tokenStart, final int tokenEnd) {
        final int equals = jdbcUrl.indexOf('=', tokenStart);
        final int nameEnd = equals == -1 || equals > tokenEnd ? tokenEnd : equals;
        return jdbcUrl.substring(tokenStart, nameEnd);
    }

    private static String parameterValue(final String jdbcUrl, final int tokenStart, final int tokenEnd) {
        final int equals = jdbcUrl.indexOf('=', tokenStart);
        if (equals == -1 || equals > tokenEnd) {
            return "";
        }
        return jdbcUrl.substring(equals + 1, tokenEnd);
    }

    private static boolean isUnsafeParameter(final String jdbcUrl, final int tokenStart, final int tokenEnd) {
        final String rawName = parameterName(jdbcUrl, tokenStart, tokenEnd);
        final String name = decodeParameterName(rawName).toLowerCase(Locale.ROOT);
        if (UNSAFE_QUERY_PARAMETERS.contains(name)) {
            return true;
        }
        return switch (name) {
            case "sslmode" -> !isSecureSslMode(parameterValue(jdbcUrl, tokenStart, tokenEnd));
            case "ssl" -> !isEnabledOrEmptySslFlag(parameterValue(jdbcUrl, tokenStart, tokenEnd));
            case "channelbinding" -> !isSecureChannelBinding(parameterValue(jdbcUrl, tokenStart, tokenEnd));
            case "gssencmode" -> !isRequiredGssEncryption(parameterValue(jdbcUrl, tokenStart, tokenEnd));
            case "preferquerymode" -> isSimpleQueryMode(parameterValue(jdbcUrl, tokenStart, tokenEnd));
            default -> false;
        };
    }

    private static boolean isSecureSslMode(final String rawValue) {
        return SECURE_SSL_MODES.contains(decodeParameterValue(rawValue).toLowerCase(Locale.ROOT));
    }

    private static boolean isEnabledOrEmptySslFlag(final String rawValue) {
        final String value = decodeParameterValue(rawValue).toLowerCase(Locale.ROOT);
        return value.isEmpty() || "true".equals(value);
    }

    private static boolean isSecureChannelBinding(final String rawValue) {
        final String value = decodeParameterValue(rawValue).toLowerCase(Locale.ROOT);
        return "prefer".equals(value) || "require".equals(value);
    }

    private static boolean isRequiredGssEncryption(final String rawValue) {
        return "require".equals(decodeParameterValue(rawValue).toLowerCase(Locale.ROOT));
    }

    private static boolean isSimpleQueryMode(final String rawValue) {
        return "simple".equals(decodeParameterValue(rawValue).toLowerCase(Locale.ROOT));
    }

    private static String decodeParameterName(final String rawName) {
        return decodeQueryComponent(rawName);
    }

    private static String decodeParameterValue(final String rawValue) {
        return decodeQueryComponent(rawValue);
    }

    private static String decodeQueryComponent(final String rawValue) {
        try {
            return URLDecoder.decode(rawValue, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return rawValue;
        }
    }
}
