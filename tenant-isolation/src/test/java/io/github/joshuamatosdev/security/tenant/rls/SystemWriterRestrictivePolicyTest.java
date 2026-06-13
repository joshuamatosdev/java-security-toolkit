package io.github.joshuamatosdev.security.tenant.rls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.shared.TenantId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proves the system-writer tier: a dedicated {@code NOBYPASSRLS} pool role that may write ONLY
 * system-owned rows pinned to the single {@code SYSTEM_OPS} sentinel tenant, enforced by a
 * RESTRICTIVE policy that ANDs with the ordinary tenant policy.
 *
 * <p>The decisive case is {@link #systemWriterCannotWriteForeignTenantRowEvenWithAValidCapturedClaim()}:
 * even holding {@code INSERT} and a <em>validly signed</em> claim for another tenant, the writer
 * cannot escalate a system write into that tenant. The cap is the database's, not the application's
 * choice to mint the right claim.
 *
 * <p>Why this is important to test: a privileged system-write path is exactly where a captured or
 * mis-scoped claim would let platform code cross the tenant boundary.
 */
class SystemWriterRestrictivePolicyTest extends AbstractRlsTest {

    private static final String SYSTEM_WRITER_USERNAME = "tenant_system_writer";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String TENANT_CLAIM_VERSION_PREFIX = "v2:";
    private static final String SET_TENANT_CLAIM_SQL_PREFIX = "SET app.tenant_claim = '";
    private static final String MINT_SENTINEL_CLAIM_SQL = "SELECT tenant_security.mint_system_ops_claim()";
    private static final String INSERT_SYSTEM_AUDIT_SQL =
            "INSERT INTO system_audit (event, detail) VALUES ('provisioned', 'tenant onboarded')";
    private static final String COUNT_SYSTEM_AUDIT_SQL = "SELECT count(*) FROM system_audit";
    private static final String PERMISSION_DENIED_MESSAGE = "permission denied";
    private static final String RLS_POLICY_MESSAGE = "row-level security policy";

    /** Truncates the shared singleton ledger so each test starts from a clean, deterministic state. */
    @BeforeEach
    void cleanSystemAudit() throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement()) {
            st.execute("TRUNCATE TABLE system_audit");
        }
    }

    @Test
    void systemWriterWritesASentinelRowAfterMintingTheSentinelClaim() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), SYSTEM_WRITER_USERNAME, DEV_PASSWORD)) {
            // The minted claim is bound transaction-locally, so the mint and the write share one
            // transaction — exactly how a system-ops write adapter frames the unit of work.
            c.setAutoCommit(false);
            try (Statement st = c.createStatement()) {
                final UUID boundTenant;
                try (ResultSet rs = st.executeQuery(MINT_SENTINEL_CLAIM_SQL)) {
                    assertThat(rs.next()).isTrue();
                    boundTenant = (UUID) rs.getObject(1);
                }
                assertThat(boundTenant)
                        .as("the minter binds exactly the SYSTEM_OPS sentinel tenant")
                        .isEqualTo(TenantIds.SYSTEM_OPS.value());

                st.executeUpdate(INSERT_SYSTEM_AUDIT_SQL);
                c.commit();
            }
        }

        // Read back as the bootstrap superuser: the writer holds SELECT only on id, not on the body.
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery("SELECT tenant_id FROM system_audit")) {
            assertThat(rs.next()).as("the system write persisted exactly one row").isTrue();
            assertThat((UUID) rs.getObject("tenant_id"))
                    .as("every system_audit row is pinned to the SYSTEM_OPS sentinel tenant")
                    .isEqualTo(TenantIds.SYSTEM_OPS.value());
            assertThat(rs.next()).as("exactly one row, no more").isFalse();
        }
    }

    @Test
    void systemWriterCannotWriteForeignTenantRowEvenWithAValidCapturedClaim() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), SYSTEM_WRITER_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            // A VALID claim for ACME, signed with the real secret — not a forgery. It would satisfy the
            // ordinary permissive WITH CHECK. The RESTRICTIVE cap rejects it anyway: the system writer
            // is pinned to the sentinel, so a captured valid claim for another tenant cannot escalate.
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX
                    + signedClaim(TenantIds.ACME, Instant.now().plusSeconds(300).getEpochSecond()) + "'");

            assertThatThrownBy(() -> st.executeUpdate(INSERT_SYSTEM_AUDIT_SQL))
                    .hasStackTraceContaining(RLS_POLICY_MESSAGE);
        }

        assertSystemAuditIsEmpty();
    }

    @Test
    void ordinaryRuntimePoolCannotMintTheSentinelClaim() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            // EXECUTE on the minter is granted only to tenant_system_writer, so the runtime pool cannot
            // obtain a sentinel claim and therefore cannot satisfy the RESTRICTIVE cap by other means.
            assertThatThrownBy(() -> st.execute(MINT_SENTINEL_CLAIM_SQL))
                    .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
        }
    }

    @Test
    void ordinaryRuntimePoolCannotWriteToTheSystemLedger() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            // The runtime pool has no INSERT grant on system_audit at all — the system-write path is not
            // merely policy-capped for it, it is ungranted.
            st.execute(SET_TENANT_CLAIM_SQL_PREFIX
                    + signedClaim(TenantIds.ACME, Instant.now().plusSeconds(300).getEpochSecond()) + "'");

            assertThatThrownBy(() -> st.executeUpdate(INSERT_SYSTEM_AUDIT_SQL))
                    .hasStackTraceContaining(PERMISSION_DENIED_MESSAGE);
        }

        assertSystemAuditIsEmpty();
    }

    @Test
    void systemWriterRoleIsNonSuperuserNonBypassAndNotABypassMember() throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(
                        "SELECT r.rolcanlogin, r.rolsuper, r.rolbypassrls, "
                                + "pg_has_role('tenant_system_writer', 'tenant_bypass', 'USAGE') AS is_bypass_member, "
                                + "pg_has_role('tenant_system_writer', 'tenant_app', 'USAGE') AS is_app_member "
                                + "FROM pg_roles r WHERE r.rolname = 'tenant_system_writer'")) {
            assertThat(rs.next()).as("the system-writer role exists").isTrue();
            assertThat(rs.getBoolean("rolcanlogin"))
                    .as("system-writer is a LOGIN role — its own pool connects as it")
                    .isTrue();
            assertThat(rs.getBoolean("rolsuper"))
                    .as("system-writer must not be a superuser")
                    .isFalse();
            assertThat(rs.getBoolean("rolbypassrls"))
                    .as("system-writer must not carry BYPASSRLS — it writes the sentinel only via a minted claim")
                    .isFalse();
            assertThat(rs.getBoolean("is_bypass_member"))
                    .as("system-writer must not be a tenant_bypass member — it is a writer, not a cross-tenant reader")
                    .isFalse();
            assertThat(rs.getBoolean("is_app_member"))
                    .as("system-writer must not inherit ordinary tenant privileges (tenant_app)")
                    .isFalse();
        }
    }

    private void assertSystemAuditIsEmpty() throws Exception {
        try (Connection c = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(COUNT_SYSTEM_AUDIT_SQL)) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getLong(1)).as("no system_audit row may have been written").isZero();
        }
    }

    /** A claim signed with the real DB secret, mirroring {@code TenantClaimSigner} (HMAC over v2:uuid:exp). */
    private static String signedClaim(final TenantId tenant, final long expEpochSeconds) throws Exception {
        final String payload = TENANT_CLAIM_VERSION_PREFIX + tenant.value() + ":" + expEpochSeconds;
        final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(CLAIM_SECRET.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
        return payload + ":" + HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
