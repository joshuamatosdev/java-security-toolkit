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
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?service=tenant-admin")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(JDBC_URL + "?sslpassword=secret")).isTrue();
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslpasswordcallback=com.example.SecretCallback"))
                .isTrue();
    }

    @Test
    void ignoresNonCredentialQueryParameters() {
        assertThat(PostgresJdbcUrls.containsCredentialQueryParameter(
                        JDBC_URL + "?sslmode=require&currentSchema=tenant_acme"))
                .isFalse();
    }
}
