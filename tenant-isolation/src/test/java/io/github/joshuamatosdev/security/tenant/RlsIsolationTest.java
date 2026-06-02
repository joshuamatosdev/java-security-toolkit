package io.github.joshuamatosdev.security.tenant;

import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.testfixtures.WithTenant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves tenant isolation is enforced by the database, not by query predicates: the repository has
 * no tenant filter anywhere, yet reads, writes, and the unbound case all behave correctly.
 */
class RlsIsolationTest extends AbstractRlsTest {

    @Autowired
    private DocumentRepository repository;

    @Autowired
    private DataSource dataSource;

    @Test
    void readsOnlyTheBoundTenantsRows() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, "acme doc", "x");
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX, "globex doc", "y");

        var acmeView = WithTenant.supplyAs(TenantIds.ACME, repository::findAll);

        assertThat(acmeView).hasSize(1);
        assertThat(acmeView.get(0).getTenantId()).isEqualTo(TenantIds.ACME.value());
    }

    @Test
    void systemOpsSeesAllTenants() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME, "acme doc", "x");
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX, "globex doc", "y");

        long all = TenantContext.supplyAsSystemOps(repository::count);

        assertThat(all).isEqualTo(2L);
    }

    @Test
    void stampsTenantFromSessionOnInsert() {
        var id = UUID.randomUUID();
        WithTenant.runAs(TenantIds.ACME, () -> repository.save(new DocumentEntity(id, "fresh", "z")));

        var asAcme = WithTenant.supplyAs(TenantIds.ACME, () -> repository.findById(id));
        assertThat(asAcme).isPresent();
        assertThat(asAcme.get().getTenantId()).isEqualTo(TenantIds.ACME.value());

        var asGlobex = WithTenant.supplyAs(TenantIds.GLOBEX, () -> repository.findById(id));
        assertThat(asGlobex).isEmpty();
    }

    @Test
    void rejectsACrossTenantWrite() {
        var jdbc = new JdbcTemplate(dataSource);

        assertThatThrownBy(() -> WithTenant.runAs(TenantIds.ACME, () -> jdbc.update(
                        "INSERT INTO document (id, tenant_id, title, body) VALUES (?, ?, ?, ?)",
                        UUID.randomUUID(),
                        TenantIds.GLOBEX.value(),
                        "smuggled",
                        "z")))
                .hasStackTraceContaining("row-level security policy");
    }

    @Test
    void failsClosedWhenNoTenantIsBound() {
        assertThatThrownBy(repository::findAll).hasStackTraceContaining("TenantContext not populated");
    }
}
