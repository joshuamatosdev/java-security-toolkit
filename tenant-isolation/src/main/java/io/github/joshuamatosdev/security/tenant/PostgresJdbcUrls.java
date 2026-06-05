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
 * instead of accepting user/password fragments hidden in JDBC URLs.
 */
public final class PostgresJdbcUrls {

    private static final Set<String> CREDENTIAL_QUERY_PARAMETERS =
            Set.of("password", "service", "sslpassword", "sslpasswordcallback", "user", "username");

    private PostgresJdbcUrls() {}

    /**
     * Detects query parameters that can carry or indirectly source connection credentials.
     *
     * @param jdbcUrl PostgreSQL JDBC URL
     * @return true when the query string contains a credential parameter
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
            if (tokenEnd > tokenStart && isCredentialParameter(parameterName(jdbcUrl, tokenStart, tokenEnd))) {
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

    private static boolean isCredentialParameter(final String rawName) {
        final String name = decodeParameterName(rawName).toLowerCase(Locale.ROOT);
        return CREDENTIAL_QUERY_PARAMETERS.contains(name);
    }

    private static String decodeParameterName(final String rawName) {
        try {
            return URLDecoder.decode(rawName, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return rawName;
        }
    }
}
