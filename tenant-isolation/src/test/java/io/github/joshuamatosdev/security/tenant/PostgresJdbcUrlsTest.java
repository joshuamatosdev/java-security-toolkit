package io.github.joshuamatosdev.security.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Postgres Jdbc Urls test coverage.
 *
 * <p>Why this is important to test: tenant isolation is a data boundary, and regressions can expose
 * one tenant to another without obvious application errors.
 */
class PostgresJdbcUrlsTest {

    private static final String JDBC_URL = "jdbc:postgresql://db/acme";

    @ParameterizedTest
    @MethodSource("blockedByNameParameters")
    void detectsBlockedByNameParameters(final String parameterName) {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?" + parameterName + "=value"))
                .isTrue();
    }

    @ParameterizedTest
    @MethodSource("blockedByValueQueries")
    void detectsBlockedByValueParameters(final String query) {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?" + query)).isTrue();
    }

    @ParameterizedTest
    @MethodSource("allowedQueries")
    void allowsExplicitlySafeParameters(final String query) {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?" + query)).isFalse();
    }

    @Test
    void treatsUnknownParametersAsUnsafe() {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?unknownDriverKnob=true"))
                .isTrue();
    }

    @Test
    void detectsPercentEncodedNamesAndValues() {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?u%73er=postgres")).isTrue();
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?allow%45ncodingChanges=true"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?sslmode=%70refer")).isTrue();
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?connect%54imeout=10")).isFalse();
    }

    @Test
    void treatsMalformedEncodedNamesAndValuesAsUnsafe() {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?bad%zz=1")).isTrue();
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(JDBC_URL + "?connectTimeout=%zz")).isTrue();
    }

    @Test
    void reportsFirstUnsafeParameterNameWithoutValue() {
        assertThat(PostgresJdbcUrls.firstUnsafeQueryParameter(
                        JDBC_URL + "?connectTimeout=10&password=secret"))
                .contains("password");
    }

    @Test
    void reportsDecodedControlCharactersEscapedInUnsafeParameterName() {
        final var unsafeParameter =
                PostgresJdbcUrls.firstUnsafeQueryParameter(JDBC_URL + "?bad%0Aname=1");

        assertThat(unsafeParameter).contains("bad" + "\\u" + "000a" + "name");
        assertThat(unsafeParameter.orElseThrow()).doesNotContain("\n");
    }

    @Test
    void ignoresEmptyQueryTokens() {
        assertThat(PostgresJdbcUrls.containsUnsafeQueryParameter(
                        JDBC_URL + "?&connectTimeout=10&&ssl=true"))
                .isFalse();
    }

    @Test
    void classifiesEveryPinnedPgJdbcProperty() throws Exception {
        final Set<String> pgJdbcPropertyNames = pgJdbcPropertyNames();

        assertThat(PostgresJdbcUrls.classifiedQueryParameterNames()).containsAll(pgJdbcPropertyNames);

        final Set<String> stalePolicyNames = new TreeSet<>(PostgresJdbcUrls.classifiedQueryParameterNames());
        stalePolicyNames.removeAll(pgJdbcPropertyNames);
        stalePolicyNames.removeAll(PostgresJdbcUrls.extraPolicyParameterNames());
        assertThat(stalePolicyNames).isEmpty();
    }

    private static Stream<String> blockedByNameParameters() {
        return Stream.of(
                "adaptiveFetch",
                "adaptiveFetchMaximum",
                "adaptiveFetchMinimum",
                "allowEncodingChanges",
                "ApplicationName",
                "assumeMinServerVersion",
                "authenticationPluginClassName",
                "autosave",
                "binaryTransfer",
                "binaryTransferDisable",
                "binaryTransferEnable",
                "cleanupSavepoints",
                "convertBooleanToNumeric",
                "currentSchema",
                "databaseMetadataCacheFields",
                "databaseMetadataCacheFieldsMiB",
                "defaultRowFetchSize",
                "disableColumnSanitiser",
                "escapeSyntaxCallMode",
                "groupStartupParameters",
                "gsslib",
                "gssUseDefaultCreds",
                "hideUnprivilegedObjects",
                "hostRecheckSeconds",
                "jaasApplicationName",
                "jaasLogin",
                "kerberosServerName",
                "loadBalanceHosts",
                "localSocketAddress",
                "loggerFile",
                "logServerErrorDetail",
                "logUnclosedConnections",
                "maxResultBuffer",
                "maxSendBufferSize",
                "options",
                "password",
                "pemKeyAlgorithm",
                "PGDBNAME",
                "PGHOST",
                "PGPORT",
                "preparedStatementCacheQueries",
                "preparedStatementCacheSizeMiB",
                "prepareThreshold",
                "protocolVersion",
                "quoteReturningIdentifiers",
                "readOnly",
                "readOnlyMode",
                "receiveBufferSize",
                "replication",
                "requireAuth",
                "reWriteBatchedInserts",
                "scramMaxIterations",
                "sendBufferSize",
                "service",
                "socketFactory",
                "socketFactoryArg",
                "sslcert",
                "sslfactory",
                "sslfactoryarg",
                "sslhostnameverifier",
                "sslkey",
                "sslpassword",
                "sslpasswordcallback",
                "sslrootcert",
                "sspiServiceClass",
                "stringtype",
                "targetServerType",
                "unknownLength",
                "user",
                "username",
                "useSpnego",
                "xmlFactoryFactory");
    }

    private static Stream<String> blockedByValueQueries() {
        return Stream.of(
                "sslmode=disable",
                "sslmode=allow",
                "sslmode=prefer",
                "SSLMode=disable",
                "sslmode=",
                "sslmode=unexpected",
                "ssl=false",
                "ssl=0",
                "channelBinding=disable",
                "channelBinding=",
                "gssEncMode=disable",
                "gssEncMode=allow",
                "gssEncMode=prefer",
                "preferQueryMode=simple",
                "PreferQueryMode=simple",
                "preferQueryMode=",
                "preferQueryMode=unknown",
                "connectTimeout",
                "connectTimeout=",
                "connectTimeout=-1",
                "connectTimeout=fast",
                "tcpKeepAlive",
                "tcpKeepAlive=maybe",
                "loggerLevel=DEBUG",
                "loggerLevel=TRACE",
                "sslNegotiation=direct",
                "sslNegotiation=");
    }

    private static Stream<String> allowedQueries() {
        return Stream.of(
                "cancelSignalTimeout=10",
                "connectTimeout=10",
                "gssResponseTimeout=5000",
                "loginTimeout=1",
                "queryTimeout=0",
                "socketTimeout=30",
                "sslResponseTimeout=5000",
                "loggerLevel=OFF",
                "tcpKeepAlive=true",
                "tcpNoDelay=false",
                "ssl",
                "ssl=",
                "ssl=true",
                "sslmode=require",
                "sslmode=verify-ca",
                "sslmode=verify-full",
                "channelBinding=prefer",
                "channelBinding=require",
                "gssEncMode=require",
                "preferQueryMode=extended",
                "preferQueryMode=extendedForPrepared",
                "preferQueryMode=extendedCacheEverything",
                "sslNegotiation=postgres",
                "sslmode=require&connectTimeout=10",
                "ssl=true&connectTimeout=10",
                "ssl&connectTimeout=10");
    }

    private static Set<String> pgJdbcPropertyNames() throws Exception {
        final Class<?> pgProperty = Class.forName("org.postgresql.PGProperty");
        final Method values = pgProperty.getMethod("values");
        final Method getName = pgProperty.getMethod("getName");
        final Object[] properties = (Object[]) values.invoke(null);
        final Set<String> names = new TreeSet<>();
        for (final Object property : properties) {
            names.add(((String) getName.invoke(property)).toLowerCase(Locale.ROOT));
        }
        return names;
    }
}
