package io.github.joshuamatosdev.security.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Postgres Jdbc Urls test coverage.
 *
 * <p>Why this is important to test: tenant isolation is a data boundary, and regressions can expose
 * one tenant to another without obvious application errors.
 */
class PostgresJdbcUrlsTest {

    private static final String JDBC_URL = "jdbc:postgresql://db/acme";

    @Test
    void detectsDirectAndIndirectCredentialQueryParameters() {
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?user=postgres")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?password=secret")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?PGHOST=evil.example")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?PGPORT=6543")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?PGDBNAME=otherdb")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?targetServerType=preferSecondary"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?hostRecheckSeconds=0")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?loadBalanceHosts=true")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?service=tenant-admin")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?authenticationPluginClassName=com.example.SecretPlugin"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gssUseDefaultCreds=true"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?jaasApplicationName=tenant"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?jaasLogin=true")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?kerberosServerName=postgres"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gsslib=sspi")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sspiServiceClass=POSTGRES"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?useSpnego=true")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?replication=database")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?requireAuth=none")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?scramMaxIterations=0")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?ScramMaxIterations=200000"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?socketFactory=com.example.SocketFactory"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?socketFactoryArg=classpath:secret.xml"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslcert=/run/secrets/client.crt"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslFactory=com.example.SslFactory"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslFactoryArg=classpath:secret.xml"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslHostnameVerifier=com.example.Verifier"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslkey=/run/secrets/client.pk8"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslpassword=secret")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslpasswordcallback=com.example.SecretCallback"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslrootcert=/run/secrets/root.crt"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?xmlFactoryFactory=com.example.UnsafeXmlFactoryFactory"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?currentSchema=tenant_acme"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?options=-c%20search_path=tenant_acme"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?UsEr=postgres")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?u%73er=postgres")).isTrue();
    }

    @Test
    void detectsExplicitTransportDowngradeParameters() {
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=disable")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=allow")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=prefer")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?SSLMode=disable")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=%70refer")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=unexpected")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?ssl=false")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?ssl=0")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?allowEncodingChanges=true"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?allow%45ncodingChanges=true"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?channelBinding=disable")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?channelBinding=")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gssEncMode=disable")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gssEncMode=allow")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gssEncMode=prefer")).isTrue();
    }

    @Test
    void detectsSimpleQueryModeDowngradeParameter() {
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?preferQueryMode=simple"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?PreferQueryMode=simple"))
                .isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?preferQueryMode=%73imple"))
                .isTrue();
    }

    @Test
    void ignoresNonCredentialQueryParameters() {
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslmode=require&connectTimeout=10"))
                .isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=verify-ca")).isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslmode=verify-full")).isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?ssl=true&connectTimeout=10"))
                .isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?ssl&connectTimeout=10")).isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?channelBinding=prefer"))
                .isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?channelBinding=require"))
                .isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?gssEncMode=require")).isFalse();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?preferQueryMode=extended"))
                .isFalse();
    }
}
