package io.github.joshuamatosdev.security.tenant.datasource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.Array;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
class ResettingConnectionProxyIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:18-alpine");

    @Test
    void arrayResultSetCannotExposeThePhysicalPooledConnection() throws Exception {
        try (HikariDataSource pool = pool();
                Connection guarded = guard(pool.getConnection())) {
            final Array array = guarded.createArrayOf("text", new Object[] {"one", "two"});
            try (ResultSet resultSet = array.getResultSet()) {
                assertThat(resultSet.getStatement().getConnection()).isSameAs(guarded);
            } finally {
                array.free();
            }
        }
    }

    @Test
    void retainedMetadataRejectsCallsAfterItsGuardedConnectionCloses() throws Exception {
        try (HikariDataSource pool = pool()) {
            final DatabaseMetaData metadata;
            try (Connection guarded = guard(pool.getConnection())) {
                metadata = guarded.getMetaData();
            }

            try (Connection borrower = pool.getConnection()) {
                assertThatThrownBy(() -> {
                            try (ResultSet ignored = metadata.getTables(null, null, "%", null)) {
                                // Calling the retained child must fail before reaching the reused connection.
                            }
                        })
                        .isInstanceOf(java.sql.SQLException.class)
                        .hasMessage("guarded connection is closed");
            }
        }
    }

    @Test
    void successfulAbortReleasesTheHikariLeaseAndAllowsReplacement() throws Exception {
        try (HikariDataSource pool = pool()) {
            final Connection borrowed = pool.getConnection();
            try {
                ResettingConnectionProxy.abortQuietly(borrowed);

                assertThat(borrowed.isClosed()).isTrue();
                assertThat(pool.getHikariPoolMXBean().getActiveConnections()).isZero();
                assertThatCode(() -> {
                            try (Connection ignored = pool.getConnection()) {
                                // A replacement physical connection must remain obtainable.
                            }
                        })
                        .doesNotThrowAnyException();
            } finally {
                borrowed.close();
            }
        }
    }

    private static Connection guard(final Connection delegate) {
        return ResettingConnectionProxy.wrap(
                delegate,
                "guarded connection is closed",
                "guarded connection does not expose its delegate",
                Connection::close);
    }

    private static HikariDataSource pool() {
        final HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMinimumIdle(0);
        config.setMaximumPoolSize(1);
        config.setConnectionTimeout(500);
        return new HikariDataSource(config);
    }
}
