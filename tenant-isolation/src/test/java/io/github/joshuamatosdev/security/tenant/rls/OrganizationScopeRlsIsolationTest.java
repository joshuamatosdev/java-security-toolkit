package io.github.joshuamatosdev.security.tenant.rls;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Proves the organization dimension is enforced by the database, not by query predicates: the
 * repository has no organization filter anywhere, yet an organization-bound session reads and
 * writes only its own organization's rows within the tenant, an organization-unscoped session
 * keeps whole-tenant visibility, and claim-kind separation holds ({@code v2} tenant claims are
 * rejected by the organization verifier).
 *
 * <p>Runs with {@code tenant.binding.organization-scope=optional}, the migration posture: the
 * proxy emits the signed organization claim whenever the binding carries one.
 *
 * <p>Why this is important to test: organization scope subdivides a tenant as defense in depth;
 * if it silently degraded to convention, a within-tenant boundary would exist only in application
 * code.
 */
class OrganizationScopeRlsIsolationTest extends AbstractRlsTest {

    private static final String COUNT_DOCUMENTS_SQL = "SELECT count(*) FROM document";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final OrganizationId ENGINEERING =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
    private static final OrganizationId LOGISTICS =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e2");
    private static final String ENGINEERING_TITLE = "engineering doc";
    private static final String LOGISTICS_TITLE = "logistics doc";
    private static final String UNASSIGNED_TITLE = "unassigned doc";

    @DynamicPropertySource
    static void organizationScope(final DynamicPropertyRegistry registry) {
        registry.add("tenant.binding.organization-scope", () -> "optional");
    }

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Test
    void organizationBoundSessionReadsOnlyItsOrganizationsRows() throws Exception {
        seedTenantWithTwoOrganizations();

        var engineeringView = tenantContext.supplyAs(TenantIds.ACME, ENGINEERING, repository::findAll);

        assertThat(engineeringView).hasSize(1);
        assertThat(engineeringView.getFirst().getTitle()).isEqualTo(ENGINEERING_TITLE);
    }

    @Test
    void organizationUnscopedSessionSeesTheWholeTenant() throws Exception {
        seedTenantWithTwoOrganizations();

        var tenantView = tenantContext.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(tenantView)
                .extracting(DocumentEntity::getTitle)
                .containsExactlyInAnyOrder(ENGINEERING_TITLE, LOGISTICS_TITLE, UNASSIGNED_TITLE);
    }

    @Test
    void organizationScopeDoesNotWeakenTheTenantBoundary() throws Exception {
        seedTenantWithTwoOrganizations();
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX, ENGINEERING,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        var globexEngineering = tenantContext.supplyAs(TenantIds.GLOBEX, ENGINEERING, repository::findAll);

        assertThat(globexEngineering)
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.GLOBEX_DOCUMENT_TITLE);
    }

    @Test
    void stampsOrganizationFromSessionOnInsert() {
        var id = tenantContext.supplyAs(TenantIds.ACME, ENGINEERING,
                () -> repository.save(new DocumentEntity("fresh", "z")).getId());

        var jdbc = new JdbcTemplate(dataSource);
        var stampedOrganization = tenantContext.supplyAs(TenantIds.ACME, ENGINEERING,
                () -> jdbc.queryForObject(
                        "SELECT organization_id FROM document WHERE id = ?", UUID.class, id));

        assertThat(stampedOrganization).isEqualTo(ENGINEERING.value());
        assertThat(tenantContext.supplyAs(TenantIds.ACME, LOGISTICS, () -> repository.findById(id)))
                .as("another organization's session must not see the row")
                .isEmpty();
    }

    @Test
    void crossOrganizationUpdatesAreFilteredByRls() throws Exception {
        seedTenantWithTwoOrganizations();
        var jdbc = new JdbcTemplate(dataSource);

        int updated = tenantContext.supplyAs(TenantIds.ACME, ENGINEERING,
                () -> jdbc.update("UPDATE document SET title = ? WHERE title = ?", "stolen", LOGISTICS_TITLE));

        assertThat(updated)
                .as("the logistics row is invisible to an engineering-bound session, so 0 rows update")
                .isZero();
        var unscopedTitles = tenantContext.supplyAs(TenantIds.ACME, repository::findAll);
        assertThat(unscopedTitles)
                .extracting(DocumentEntity::getTitle)
                .contains(LOGISTICS_TITLE);
    }

    @Test
    void organizationUnscopedInsertStaysInvisibleToOrganizationBoundSessions() {
        var id = tenantContext.supplyAs(TenantIds.ACME,
                () -> repository.save(new DocumentEntity(UNASSIGNED_TITLE, "z")).getId());

        assertThat(tenantContext.supplyAs(TenantIds.ACME, ENGINEERING, () -> repository.findById(id)))
                .as("rows with no organization stay tenant-admin material")
                .isEmpty();
        assertThat(tenantContext.supplyAs(TenantIds.ACME, () -> repository.findById(id)))
                .isPresent();
    }

    @Test
    void tenantClaimReplayedIntoTheOrganizationSettingIsRejected() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            // A VALIDLY signed v2 tenant claim placed in app.org_claim must fail the v2o kind check.
            st.execute("SET app.org_claim = '"
                    + signedClaim("v2", TenantIds.ACME.value(), farFutureEpoch()) + "'");

            try (var rs = st.executeQuery("SELECT tenant_security.current_org_id() IS NULL")) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getBoolean(1))
                        .as("claim kinds are separated by the signed version marker")
                        .isTrue();
            }
        }
    }

    @Test
    void locallySignedOrganizationClaimIsHonoredByTheVerifier() throws Exception {
        seedTenantWithTwoOrganizations();

        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            st.execute("SET app.tenant_claim = '"
                    + signedClaim("v2", TenantIds.ACME.value(), farFutureEpoch()) + "'");
            st.execute("SET app.org_claim = '"
                    + signedClaim("v2o", ENGINEERING.value(), farFutureEpoch()) + "'");

            try (var rs = st.executeQuery(COUNT_DOCUMENTS_SQL)) {
                assertThat(rs.next()).isTrue();
                assertThat(rs.getLong(1))
                        .as("a valid v2o organization claim scopes the session to one organization")
                        .isEqualTo(1L);
            }
        }
    }

    private static void seedTenantWithTwoOrganizations() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, ENGINEERING,
                ENGINEERING_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, LOGISTICS,
                LOGISTICS_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                UNASSIGNED_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
    }

    private static long farFutureEpoch() {
        return Instant.now().plusSeconds(300).getEpochSecond();
    }

    /** A claim signed with the real DB secret, mirroring {@code TenantClaimSigner} (HMAC over version:uuid:exp). */
    private static String signedClaim(final String version, final UUID id, final long expEpochSeconds)
            throws Exception {
        final String payload = version + ":" + id + ":" + expEpochSeconds;
        final Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(CLAIM_SECRET.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
        return payload + ":" + HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
