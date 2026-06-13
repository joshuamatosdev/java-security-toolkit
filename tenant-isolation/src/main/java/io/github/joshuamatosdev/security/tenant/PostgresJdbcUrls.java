package io.github.joshuamatosdev.security.tenant;

import static java.util.Map.entry;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * PostgreSQL JDBC URL guards shared by tenant datasource configuration.
 *
 * <p>Why this exists: pool creation must keep identity, target, auth, trust, plugin, driver
 * behavior, and session-startup controls under trusted configuration instead of accepting hidden
 * overrides in tenant placement URLs.
 */
public final class PostgresJdbcUrls {

    private static final QueryParameterPolicy BLOCKED = (rawValue, hasValue) -> true;

    private static final Map<String, QueryParameterPolicy> QUERY_PARAMETER_POLICIES =
            Map.ofEntries(
                    entry("adaptivefetch", BLOCKED),
                    entry("adaptivefetchmaximum", BLOCKED),
                    entry("adaptivefetchminimum", BLOCKED),
                    entry("allowencodingchanges", BLOCKED),
                    entry("applicationname", BLOCKED),
                    entry("assumeminserverversion", BLOCKED),
                    entry("authenticationpluginclassname", BLOCKED),
                    entry("autosave", BLOCKED),
                    entry("binarytransfer", BLOCKED),
                    entry("binarytransferdisable", BLOCKED),
                    entry("binarytransferenable", BLOCKED),
                    entry("cancelsignaltimeout", nonNegativeInteger()),
                    entry("channelbinding", allowedValues(false, "prefer", "require")),
                    entry("cleanupsavepoints", BLOCKED),
                    entry("connecttimeout", nonNegativeInteger()),
                    entry("convertbooleantonumeric", BLOCKED),
                    entry("currentschema", BLOCKED),
                    entry("databasemetadatacachefields", BLOCKED),
                    entry("databasemetadatacachefieldsmib", BLOCKED),
                    entry("defaultrowfetchsize", BLOCKED),
                    entry("disablecolumnsanitiser", BLOCKED),
                    entry("escapesyntaxcallmode", BLOCKED),
                    entry("groupstartupparameters", BLOCKED),
                    entry("gssencmode", allowedValues(false, "require")),
                    entry("gsslib", BLOCKED),
                    entry("gssresponsetimeout", nonNegativeInteger()),
                    entry("gssusedefaultcreds", BLOCKED),
                    entry("hideunprivilegedobjects", BLOCKED),
                    entry("hostrecheckseconds", BLOCKED),
                    entry("jaasapplicationname", BLOCKED),
                    entry("jaaslogin", BLOCKED),
                    entry("kerberosservername", BLOCKED),
                    entry("loadbalancehosts", BLOCKED),
                    entry("localsocketaddress", BLOCKED),
                    entry("loggerfile", BLOCKED),
                    entry("loggerlevel", allowedValues(false, "off")),
                    entry("logintimeout", nonNegativeInteger()),
                    entry("logservererrordetail", BLOCKED),
                    entry("logunclosedconnections", BLOCKED),
                    entry("maxresultbuffer", BLOCKED),
                    entry("maxsendbuffersize", BLOCKED),
                    entry("options", BLOCKED),
                    entry("password", BLOCKED),
                    entry("pemkeyalgorithm", BLOCKED),
                    entry("pgdbname", BLOCKED),
                    entry("pghost", BLOCKED),
                    entry("pgport", BLOCKED),
                    entry("preferquerymode", allowedValues(
                            false, "extended", "extendedforprepared", "extendedcacheeverything")),
                    entry("preparedstatementcachequeries", BLOCKED),
                    entry("preparedstatementcachesizemib", BLOCKED),
                    entry("preparethreshold", BLOCKED),
                    entry("protocolversion", BLOCKED),
                    entry("querytimeout", nonNegativeInteger()),
                    entry("quotereturningidentifiers", BLOCKED),
                    entry("readonly", BLOCKED),
                    entry("readonlymode", BLOCKED),
                    entry("receivebuffersize", BLOCKED),
                    entry("replication", BLOCKED),
                    entry("requireauth", BLOCKED),
                    entry("rewritebatchedinserts", BLOCKED),
                    entry("scrammaxiterations", BLOCKED),
                    entry("sendbuffersize", BLOCKED),
                    entry("service", BLOCKED),
                    entry("socketfactory", BLOCKED),
                    entry("socketfactoryarg", BLOCKED),
                    entry("sockettimeout", nonNegativeInteger()),
                    entry("ssl", allowedValues(true, "true")),
                    entry("sslcert", BLOCKED),
                    entry("sslfactory", BLOCKED),
                    entry("sslfactoryarg", BLOCKED),
                    entry("sslhostnameverifier", BLOCKED),
                    entry("sslkey", BLOCKED),
                    entry("sslmode", allowedValues(false, "require", "verify-ca", "verify-full")),
                    entry("sslnegotiation", allowedValues(false, "postgres")),
                    entry("sslpassword", BLOCKED),
                    entry("sslpasswordcallback", BLOCKED),
                    entry("sslresponsetimeout", nonNegativeInteger()),
                    entry("sslrootcert", BLOCKED),
                    entry("sspiserviceclass", BLOCKED),
                    entry("stringtype", BLOCKED),
                    entry("targetservertype", BLOCKED),
                    entry("tcpkeepalive", booleanValue()),
                    entry("tcpnodelay", booleanValue()),
                    entry("unknownlength", BLOCKED),
                    entry("user", BLOCKED),
                    entry("username", BLOCKED),
                    entry("usespnego", BLOCKED),
                    entry("xmlfactoryfactory", BLOCKED));

    private static final Set<String> COMPATIBILITY_ALIAS_PARAMETER_NAMES = Set.of("username");

    private PostgresJdbcUrls() {}

    /**
     * Detects query parameters that are not safe for tenant placement JDBC URLs.
     *
     * @param jdbcUrl PostgreSQL JDBC URL
     * @return true when the query string contains an unsafe or unclassified parameter
     */
    public static boolean containsUnsafeQueryParameter(final String jdbcUrl) {
        return firstUnsafeQueryParameter(jdbcUrl).isPresent();
    }

    /**
     * Returns the first unsafe parameter name without exposing its value.
     *
     * @param jdbcUrl PostgreSQL JDBC URL
     * @return first unsafe parameter name, or empty when all query parameters are safe
     */
    public static Optional<String> firstUnsafeQueryParameter(final String jdbcUrl) {
        Objects.requireNonNull(jdbcUrl, "jdbcUrl must not be null");
        int tokenStart = jdbcUrl.indexOf('?');
        if (tokenStart == -1 || tokenStart == jdbcUrl.length() - 1) {
            return Optional.empty();
        }
        tokenStart++;
        while (tokenStart < jdbcUrl.length()) {
            final int tokenEnd = nextTokenEnd(jdbcUrl, tokenStart);
            if (tokenEnd > tokenStart) {
                final QueryParameter parameter = queryParameter(jdbcUrl, tokenStart, tokenEnd);
                if (parameter.decodedName() == null) {
                    return Optional.of(reportSafeParameterName(parameter.rawName()));
                }
                final QueryParameterPolicy policy = QUERY_PARAMETER_POLICIES.get(parameter.normalizedName());
                if (policy == null || policy.rejects(parameter.rawValue(), parameter.hasValue())) {
                    return Optional.of(reportSafeParameterName(parameter.decodedName()));
                }
            }
            if (tokenEnd == jdbcUrl.length()) {
                return Optional.empty();
            }
            tokenStart = tokenEnd + 1;
        }
        return Optional.empty();
    }

    /**
     * @deprecated use {@link #containsUnsafeQueryParameter(String)}.
     */
    @Deprecated(since = "0.1.0", forRemoval = false)
    public static boolean containsCredentialQueryParameter(final String jdbcUrl) {
        return containsUnsafeQueryParameter(jdbcUrl);
    }

    static Set<String> classifiedQueryParameterNames() {
        return QUERY_PARAMETER_POLICIES.keySet();
    }

    static Set<String> compatibilityAliasParameterNames() {
        return COMPATIBILITY_ALIAS_PARAMETER_NAMES;
    }

    private static int nextTokenEnd(final String jdbcUrl, final int tokenStart) {
        final int ampersand = jdbcUrl.indexOf('&', tokenStart);
        return ampersand == -1 ? jdbcUrl.length() : ampersand;
    }

    private static QueryParameter queryParameter(final String jdbcUrl, final int tokenStart, final int tokenEnd) {
        final int equals = jdbcUrl.indexOf('=', tokenStart);
        final boolean hasValue = equals != -1 && equals <= tokenEnd;
        final int nameEnd = hasValue ? equals : tokenEnd;
        final String rawName = jdbcUrl.substring(tokenStart, nameEnd);
        final String decodedName = decodeQueryComponent(rawName);
        final String rawValue = hasValue ? jdbcUrl.substring(equals + 1, tokenEnd) : "";
        return new QueryParameter(
                rawName,
                decodedName,
                decodedName == null ? "" : normalized(decodedName),
                rawValue,
                hasValue);
    }

    private static QueryParameterPolicy allowedValues(final boolean allowEmpty, final String... values) {
        final Set<String> allowedValues = Arrays.stream(values)
                .map(PostgresJdbcUrls::normalized)
                .collect(Collectors.toUnmodifiableSet());
        return (rawValue, hasValue) -> {
            final String value = decodeQueryComponent(rawValue);
            if (value == null) {
                return true;
            }
            final String normalizedValue = normalized(value);
            if (normalizedValue.isEmpty()) {
                return !allowEmpty;
            }
            return !allowedValues.contains(normalizedValue);
        };
    }

    private static QueryParameterPolicy nonNegativeInteger() {
        return (rawValue, hasValue) -> {
            if (!hasValue) {
                return true;
            }
            final String value = decodeQueryComponent(rawValue);
            return value == null || value.isEmpty() || value.chars().anyMatch(ch -> !Character.isDigit(ch));
        };
    }

    private static QueryParameterPolicy booleanValue() {
        return (rawValue, hasValue) -> {
            if (!hasValue) {
                return true;
            }
            final String value = decodeQueryComponent(rawValue);
            if (value == null) {
                return true;
            }
            final String normalizedValue = normalized(value);
            return !"true".equals(normalizedValue) && !"false".equals(normalizedValue);
        };
    }

    private static String normalized(final String value) {
        return value.toLowerCase(Locale.ROOT);
    }

    private static String decodeQueryComponent(final String rawValue) {
        try {
            return URLDecoder.decode(rawValue, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String reportSafeParameterName(final String parameterName) {
        final StringBuilder escaped = new StringBuilder(parameterName.length());
        for (int index = 0; index < parameterName.length(); index++) {
            final char character = parameterName.charAt(index);
            if (Character.isISOControl(character)) {
                escaped.append("\\u");
                final String hex = Integer.toHexString(character);
                escaped.append("0".repeat(4 - hex.length())).append(hex);
            } else {
                escaped.append(character);
            }
        }
        return escaped.toString();
    }

    private record QueryParameter(
            String rawName,
            String decodedName,
            String normalizedName,
            String rawValue,
            boolean hasValue) {}

    @FunctionalInterface
    private interface QueryParameterPolicy {
        boolean rejects(String rawValue, boolean hasValue);
    }
}
