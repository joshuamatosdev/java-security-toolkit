package io.github.joshuamatosdev.security.tenant.rls;

import io.github.joshuamatosdev.security.tenant.testfixtures.AbstractRlsTest;

import io.github.joshuamatosdev.security.tenant.TenantIds;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.joshuamatosdev.security.tenant.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.tenant.binding.TenantContext;
import io.github.joshuamatosdev.security.tenant.testfixtures.TenantTestConstants;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;

/**
 * End-to-end proof of the tenant-before-transaction contract against a real PostgreSQL transaction
 * (not a faked synchronization flag). A transaction borrows its tenant-bound connection at begin, so
 * the tenant must be bound BEFORE the transactional boundary opens: binding it INSIDE fails closed.
 *
 * <p>The default single-datasource check ({@code isActualTransactionActive}) is in force here, which
 * is correct: the tenant-bound proxy is the only datasource on the thread.
 *
 * <p>Why this is important to test: RLS and transaction ordering only prove isolation when
 * PostgreSQL enforces them, not when application code merely assumes them.
 */
@Import(TenantTransactionOrderingTest.Fixture.class)
class TenantTransactionOrderingTest extends AbstractRlsTest {

    @Autowired
    private TransactionalReader reader;

    @Test
    void tenantBoundBeforeTheTransactionIsHonored() throws Exception {
        seedAsSuperuser(UUID.randomUUID(), TenantIds.ACME,
                TenantTestConstants.ACME_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_X);
        seedAsSuperuser(UUID.randomUUID(), TenantIds.GLOBEX,
                TenantTestConstants.GLOBEX_DOCUMENT_TITLE, TenantTestConstants.DOCUMENT_BODY_Y);

        long acmeRows = tenantContext.supplyAs(TenantIds.ACME, reader::countInTransaction);

        assertThat(acmeRows).isEqualTo(1L);
    }

    @Test
    void bindingTheTenantInsideTheTransactionFailsClosed() {
        assertThatThrownBy(reader::countBindingInsideTransaction)
                .hasStackTraceContaining(TenantTestConstants.TENANT_CONTEXT_NOT_POPULATED_MESSAGE);
    }

    @TestConfiguration
    static class Fixture {
        @Bean
        TransactionalReader transactionalReader(
                final DocumentRepository repository,
                final TenantContext tenantContext) {
            return new TransactionalReader(repository, tenantContext);
        }
    }

    /** A Spring-managed bean so {@code @Transactional} is honored by the transaction interceptor. */
    static class TransactionalReader {
        private final DocumentRepository repository;
        private final TenantContext tenantContext;

        TransactionalReader(
                final DocumentRepository repository,
                final TenantContext tenantContext) {
            this.repository = repository;
            this.tenantContext = tenantContext;
        }

        /** Correct ordering: the caller bound the tenant before this transactional boundary opened. */
        @Transactional
        long countInTransaction() {
            return repository.count();
        }

        /** Wrong ordering: opens the transaction first; the tenant-bound connection is borrowed at
         * begin, before this in-method bind runs, so the borrow fails closed. */
        @Transactional
        long countBindingInsideTransaction() {
            return tenantContext.supplyAs(TenantIds.ACME, repository::count);
        }
    }
}
