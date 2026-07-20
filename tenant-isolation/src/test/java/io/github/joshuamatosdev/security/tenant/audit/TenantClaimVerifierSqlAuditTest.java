package io.github.joshuamatosdev.security.tenant.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Static guard for tenant claim verifier parity across isolation-mode SQL fixtures.
 *
 * <p>Why this is important to test: static audits catch future code that moves UUID ownership or
 * signed-claim verification out of the database boundary.
 */
class TenantClaimVerifierSqlAuditTest {

    private static final List<Path> VERIFIER_SCRIPTS = List.of(
            Path.of("src/test/resources/db/init.sql"),
            Path.of("src/test/resources/db/schema-mode-init.sql"),
            Path.of("src/test/resources/db/database-mode-acme-init.sql"),
            Path.of("src/test/resources/db/database-mode-globex-init.sql"));

    @Test
    @DisplayName("Tenant claim SQL verifiers compare signatures through double-HMAC")
    void tenantClaimSqlVerifiersUseDoubleHmacComparison() throws IOException {
        for (Path script : VERIFIER_SCRIPTS) {
            final String sql = Files.readString(script);

            assertThat(sql)
                    .as(script + " must not compare attacker-controlled signature text directly")
                    .doesNotContain("lower(claim_signature) <> expected_signature");
            assertThat(sql)
                    .as(script + " must use a fresh comparison key for the double-HMAC comparison")
                    .contains("compare_key := encode(tenant_security.gen_random_bytes(32), 'hex')");
            assertThat(sql)
                    .as(script + " must HMAC the supplied signature before comparison")
                    .contains("tenant_security.hmac(lower(claim_signature), compare_key, 'sha256')");
            assertThat(sql)
                    .as(script + " must HMAC the expected signature before comparison")
                    .contains("tenant_security.hmac(expected_signature, compare_key, 'sha256')");
            assertThat(sql)
                    .as(script + " must fail fast if pgcrypto is installed outside tenant_security")
                    .contains("pgcrypto extension must be installed in tenant_security");
            assertThat(sql)
                    .as(script + " must expire claims against wall-clock time, not transaction-start time")
                    .contains("claim_exp_text::bigint <= extract(epoch FROM clock_timestamp())")
                    .doesNotContain(
                            "claim_exp_text::bigint <= extract(epoch FROM clock_timestamp())::bigint")
                    .doesNotContain("extract(epoch FROM now())::bigint");
            assertThat(sql)
                    .as(script + " must not mark a wall-clock/random verifier as STABLE")
                    .contains("VOLATILE")
                    .doesNotContain("STABLE");
        }
    }
}
