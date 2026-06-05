package io.github.joshuamatosdev.security.tenant.rls;

import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;

import io.github.joshuamatosdev.security.tenant.TenantIds;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import io.github.joshuamatosdev.security.tenant.testfixtures.WithTenant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves tenant isolation is enforced by the database, not by query predicates: the repository has
 * no tenant filter anywhere, yet reads, writes, and the unbound case all behave correctly.
 *
 * <p>Why this is important to test: RLS and transaction ordering only prove isolation when
 * PostgreSQL enforces them, not when application code merely assumes them.
 */
class RlsIsolationTest extends AbstractRlsTest {

    private static final String COUNT_DOCUMENTS_SQL = "SELECT count(*) FROM document";
    private static final String FRESH_DOCUMENT_TITLE = "fresh";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String INSERT_SMUGGLED_DOCUMENT_SQL =
            "INSERT INTO document (title, body) VALUES ('smuggled', 'z')";
    private static final String PERMISSION_DENIED_MESSAGE = "permission denied";
    private static final String RLS_POLICY_MESSAGE = "row-level security policy";
    private static final String SET_CURRENT_TENANT_SQL_PREFIX = "SET app.current_tenant = '";
    private static final String SET_TENANT_CLAIM_SQL_PREFIX = "SET app.tenant_claim = '";
    private static final String TENANT_CLAIM_VERSION_PREFIX = "v2:";

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Test
    void readsOnlyTheBoundTenantsRows() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        var acmeView = WithTenant.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(acmeView).hasSize(1);
        assertThat(acmeView.get(0).getTenantId()).isEqualTo(TenantIds.ACME.value());
    }

    @Test
    void systemOpsSeesAllTenants() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        long all = TenantContext.supplyAsSystemOps(repository::count);

        assertThat(all).isEqualTo(2L);
    }

    @Test
    void tenantUserCannotSelfBypassRlsBySettingLegacyOrBypassGucs() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            st.execute(SET_CURRENT_TENANT_SQL_PREFIX + TenantIds.ACME.value() + "'");
            st.execute("SET app.bypass_rls = 'on'");

            try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1)).isZero();
            }

            assertThatThrownBy(() -> st.executeUpdate(INSERT_SMUGGLED_DOCUMENT_SQL))
                    .hasStackTraceContaining(RLS_POLICY_MESSAGE);
        }
    }

    @Test
    void tenantUserCannotRetargetRlsByForgingTenantClaim() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX + forgedClaimFor(TenantIds.GLOBEX) + "'");

            try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1)).isZero();
            }

            assertThatThrownBy(() -> st.executeUpdate(INSERT_SMUGGLED_DOCUMENT_SQL))
                    .hasStackTraceContaining(RLS_POLICY_MESSAGE);
        }
    }

    @Test
    void retargetingTenantClaimInsideBorrowedConnectionFailsClosed() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        WithTenant.runAs(TenantIds.ACME, () -> {
            try (Connection c = dataSource.getConnection();
                    Statement st = c.createStatement()) {
                try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
                    assertThat(rs.next()).isTrue();
                    assertThat(rs.getLong(1)).isEqualTo(1L);
                }

                st.execute(SET_TENANT_CLAIM_SQL_PREFIX + forgedClaimFor(TenantIds.GLOBEX) + "'");
                st.execute(SET_CURRENT_TENANT_SQL_PREFIX + TenantIds.GLOBEX.value() + "'");

                try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
                    assertThat(rs.next()).isTrue();
                    assertThat(rs.getLong(1)).isZero();
                }

                assertThatThrownBy(() -> st.executeUpdate(INSERT_SMUGGLED_DOCUMENT_SQL))
                        .hasStackTraceContaining(RLS_POLICY_MESSAGE);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    @Test
    void systemOpsIsReadOnly() {
        assertThatThrownBy(() -> TenantContext.runAsSystemOps(
                        () -> repository.save(new DocumentEntity("ops write", "z"))))
                .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
    }

    @Test
    void stampsTenantFromSessionOnInsert() {
        var id = WithTenant.supplyAs(
                TenantIds.ACME, () -> repository.save(new DocumentEntity(FRESH_DOCUMENT_TITLE, "z")).getId());

        var asAcme = WithTenant.supplyAs(TenantIds.ACME, () -> repository.findById(id));
        assertThat(asAcme).isPresent();
        assertThat(asAcme.get().getTenantId()).isEqualTo(TenantIds.ACME.value());

        var asGlobex = WithTenant.supplyAs(TenantIds.GLOBEX, () -> repository.findById(id));
        assertThat(asGlobex).isEmpty();
    }

    @Test
    void databaseMintsVersion7PrimaryKeyOnInsert() {
        var saved = WithTenant.supplyAs(
                TenantIds.ACME, () -> repository.save(new DocumentEntity(FRESH_DOCUMENT_TITLE, "z")));

        assertThat(saved.getId())
                .as("the database owns id creation: the id_v7 domain default (uuidv7(), PG18) mints the key")
                .isNotNull();
        assertThat(saved.getId().version())
                .as("primary key must be a database-minted UUID version 7")
                .isEqualTo(7);
    }

    @Test
    void rejectsCallerSuppliedPrimaryKeyOnInsert() {
        var jdbc = new JdbcTemplate(dataSource);

        assertThatThrownBy(() -> WithTenant.runAs(TenantIds.ACME, () -> jdbc.update(
                        "INSERT INTO document (id, title, body) VALUES (?, ?, ?)",
                        UUID.randomUUID(),
                        "caller id",
                        "z")))
                .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
    }

    @Test
    void rejectsPrimaryKeyUpdate() {
        var id = WithTenant.supplyAs(
                TenantIds.ACME, () -> repository.save(new DocumentEntity(FRESH_DOCUMENT_TITLE, "z")).getId());
        var jdbc = new JdbcTemplate(dataSource);

        assertThatThrownBy(() -> WithTenant.runAs(TenantIds.ACME, () -> jdbc.update(
                        "UPDATE document SET id = ? WHERE id = ?",
                        UUID.randomUUID(),
                        id)))
                .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
    }

    @Test
    void rejectsCallerSuppliedTenantIdOnInsert() {
        var jdbc = new JdbcTemplate(dataSource);

        assertThatThrownBy(() -> WithTenant.runAs(TenantIds.ACME, () -> jdbc.update(
                        "INSERT INTO document (tenant_id, title, body) VALUES (?, ?, ?)",
                        TenantIds.GLOBEX.value(),
                        "smuggled",
                        "z")))
                .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
    }

    @Test
    void failsClosedWhenNoTenantIsBound() {
        assertThatThrownBy(repository::findAll)
                .hasStackTraceContaining(TenantTestConstants.TENANT_CONTEXT_NOT_POPULATED_MESSAGE);
    }

    @Test
    void validClaimIsHonoredUntilItExpires() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            // A claim signed with the real secret and a future expiry is honored.
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX
                    + signedClaim(TenantIds.ACME, Instant.now().plusSeconds(300).getEpochSecond()) + "'");
            assertThat(countDocuments(st))
                    .as("a validly signed, unexpired claim is honored")
                    .isEqualTo(1L);

            // The same secret and tenant, but an expiry in the past, reads nothing: a captured claim
            // cannot be replayed once it ages out.
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX
                    + signedClaim(TenantIds.ACME, Instant.now().minusSeconds(60).getEpochSecond()) + "'");
            assertThat(countDocuments(st))
                    .as("the same claim, expired, must read nothing")
                    .isZero();
        }
    }

    @Test
    void claimAtTheCurrentDatabaseEpochIsAlreadyExpired() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            c.setAutoCommit(false);

            final long currentDatabaseEpoch;
            try (var rs = st.executeQuery("SELECT extract(epoch FROM clock_timestamp())::bigint")) {
                rs.next();
                currentDatabaseEpoch = rs.getLong(1);
            }
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX + signedClaim(TenantIds.ACME, currentDatabaseEpoch) + "'");

            assertThat(countDocuments(st))
                    .as("a claim expiring at the current database epoch must not remain valid")
                    .isZero();

            c.rollback();
        }
    }

    @Test
    void claimExpiresAgainstWallClockInsideALongTransaction() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            c.setAutoCommit(false);

            final long transactionEpoch;
            try (var rs = st.executeQuery("SELECT extract(epoch FROM now())::bigint")) {
                rs.next();
                transactionEpoch = rs.getLong(1);
            }
            final long exp = Math.max(transactionEpoch, currentWallClockEpoch(st)) + 2;
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX + signedClaim(TenantIds.ACME, exp) + "'");

            assertThat(countDocuments(st))
                    .as("the signed claim is valid at transaction start")
                    .isEqualTo(1L);

            while (currentWallClockEpoch(st) < exp) {
                Thread.sleep(100);
            }

            assertThat(countDocuments(st))
                    .as("claim expiry must use wall-clock time, not transaction-start time")
                    .isZero();

            c.rollback();
        }
    }

    @Test
    void claimVerifierReevaluatesExpiryInsideASingleLongRunningStatement() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            final long exp = currentWallClockEpoch(st) + 2;
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX + signedClaim(TenantIds.ACME, exp) + "'");

            try (var rs = st.executeQuery("""
                    SELECT
                        tenant_security.current_tenant_id() AS before_expiry,
                        pg_sleep(3),
                        tenant_security.current_tenant_id() AS after_expiry
                    """)) {
                assertThat(rs.next()).isTrue();
                assertThat((UUID) rs.getObject("before_expiry"))
                        .as("the signed claim starts valid")
                        .isEqualTo(TenantIds.ACME.value());
                assertThat(rs.getObject("after_expiry"))
                        .as("the verifier must not cache a STABLE result past the claim expiry")
                        .isNull();
            }
        }
    }

    private static long countDocuments(final Statement st) throws Exception {
        try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static long currentWallClockEpoch(final Statement st) throws Exception {
        try (var rs = st.executeQuery("SELECT extract(epoch FROM clock_timestamp())::bigint")) {
            rs.next();
            return rs.getLong(1);
        }
    }

    /** A claim signed with the real DB secret, mirroring {@code TenantClaimSigner} (HMAC over v2:uuid:exp). */
    private static String signedClaim(final TenantId tenant, final long expEpochSeconds) throws Exception {
        final String payload = TENANT_CLAIM_VERSION_PREFIX + tenant.value() + ":" + expEpochSeconds;
        final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(CLAIM_SECRET.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
        return payload + ":" + HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }

    private static String forgedClaimFor(final TenantId tenant) {
        // Well-formed v2 claim with a far-future expiry but a bogus signature -> rejected at the HMAC check.
        return TENANT_CLAIM_VERSION_PREFIX + tenant.value() + ":4102444800:" + "0".repeat(64);
    }
}
