package io.github.joshuamatosdev.security.tenant.rls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.tenant.TenantIds;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.OffsetDateTime;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Proves cross-tenant read entitlements (ADR-0008) are enforced by the database, not by query
 * predicates: an explicit grant row is the only thing that lets one tenant read another tenant's
 * rows, the grant is directional, class-scoped, expiring, and revocable, and it can never widen a
 * write. The repository under test has no tenant or entitlement predicate anywhere.
 *
 * <p>Runs with {@code tenant.binding.organization-scope=optional} so the organization interaction
 * is provable too: the reader's own organization binding must not filter another tenant's rows.
 *
 * <p>Why this is important to test: an entitlement is a deliberate hole in the tenant read
 * boundary. Every property that keeps the hole bounded — read-only, directional, revocable,
 * unforgeable from inside a tenant session — must be executable, or the hole is just a hope.
 */
class CrossTenantReadEntitlementTest extends AbstractRlsTest {

    private static final String DOCUMENT_CLASS = "document";
    private static final String UNRELATED_CLASS = "report";
    private static final OrganizationId ENGINEERING =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e1");
    private static final OrganizationId LOGISTICS =
            OrganizationId.fromString("0190a000-0000-7000-8000-0000000000e2");
    private static final String ENGINEERING_TITLE = "engineering doc";
    private static final String LOGISTICS_TITLE = "logistics doc";

    @DynamicPropertySource
    static void organizationScope(final DynamicPropertyRegistry registry) {
        registry.add("tenant.binding.organization-scope", () -> "optional");
    }

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Test
    void entitledSessionReadsGrantorRowsWithoutAnyPredicate() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, null);

        var acmeView = TenantContext.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(acmeView)
                .extracting(DocumentEntity::getTitle)
                .containsExactlyInAnyOrder(
                        TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.GLOBEX_DOCUMENT_TITLE);
    }

    @Test
    void entitlementIsDirectional() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, null);

        var globexView = TenantContext.supplyAs(TenantIds.GLOBEX, repository::findAll);

        assertThat(globexView)
                .as("a grant from globex to acme must not open acme's rows to globex")
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.GLOBEX_DOCUMENT_TITLE);
    }

    @Test
    void entitlementIsResourceClassScoped() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, UNRELATED_CLASS, null);

        var acmeView = TenantContext.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(acmeView)
                .as("a grant for another resource class must not open document rows")
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.ACME_DOCUMENT_TITLE);
    }

    @Test
    void expiredEntitlementDeniesTheRead() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(
                TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, OffsetDateTime.now().minusSeconds(5));

        var acmeView = TenantContext.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(acmeView)
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.ACME_DOCUMENT_TITLE);
    }

    @Test
    void revokedEntitlementDeniesTheNextRead() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, null);
        var entitledView = TenantContext.supplyAs(TenantIds.ACME, repository::findAll);
        assertThat(entitledView).hasSize(2);

        revokeReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME);

        var revokedView = TenantContext.supplyAs(TenantIds.ACME, repository::findAll);
        assertThat(revokedView)
                .as("revocation is a row delete and takes effect on the next statement")
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.ACME_DOCUMENT_TITLE);
    }

    @Test
    void entitlementNeverGrantsWrites() throws Exception {
        seedOneDocumentPerTenant();
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, null);
        var jdbc = new JdbcTemplate(dataSource);

        int updated = TenantContext.supplyAs(TenantIds.ACME, () -> jdbc.update(
                "UPDATE document SET title = ? WHERE title = ?",
                "stolen", TenantTestConstants.GLOBEX_DOCUMENT_TITLE));
        int deleted = TenantContext.supplyAs(TenantIds.ACME, () -> jdbc.update(
                "DELETE FROM document WHERE title = ?", TenantTestConstants.GLOBEX_DOCUMENT_TITLE));

        assertThat(updated)
                .as("the entitlement policy is FOR SELECT, so no write plan can see the foreign row")
                .isZero();
        assertThat(deleted).isZero();
        var globexView = TenantContext.supplyAs(TenantIds.GLOBEX, repository::findAll);
        assertThat(globexView)
                .extracting(DocumentEntity::getTitle)
                .containsExactly(TenantTestConstants.GLOBEX_DOCUMENT_TITLE);
    }

    @Test
    void tenantSessionCannotMintOrEnumerateGrants() throws Exception {
        try (Connection c = DriverManager.getConnection(POSTGRES.getJdbcUrl(), RUNTIME_USERNAME, DEV_PASSWORD);
                Statement st = c.createStatement()) {
            assertThatThrownBy(() -> st.execute(
                            "INSERT INTO tenant_security.read_grant"
                                    + " (grantor_tenant_id, grantee_tenant_id, resource_class)"
                                    + " VALUES ('" + TenantIds.GLOBEX.value() + "', '"
                                    + TenantIds.ACME.value() + "', 'document')"))
                    .as("hostile SQL inside a tenant session must not be able to entitle itself")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("permission denied");
            assertThatThrownBy(() -> st.executeQuery("SELECT count(*) FROM tenant_security.read_grant"))
                    .as("the grant graph is confidential — tenants cannot enumerate who shares with whom")
                    .isInstanceOf(SQLException.class)
                    .hasMessageContaining("permission denied");
        }
    }

    @Test
    void organizationBoundSessionKeepsEntitledForeignReads() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, ENGINEERING,
                ENGINEERING_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, LOGISTICS,
                LOGISTICS_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);
        grantReadAsSuperuser(TenantIds.GLOBEX, TenantIds.ACME, DOCUMENT_CLASS, null);

        var engineeringView = TenantContext.supplyAs(TenantIds.ACME, ENGINEERING, repository::findAll);

        assertThat(engineeringView)
                .as("the reader's own organization cap scopes its own tenant, not the grantor's rows")
                .extracting(DocumentEntity::getTitle)
                .containsExactlyInAnyOrder(ENGINEERING_TITLE, TenantTestConstants.GLOBEX_DOCUMENT_TITLE);
    }

    private static void seedOneDocumentPerTenant() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);
    }
}
