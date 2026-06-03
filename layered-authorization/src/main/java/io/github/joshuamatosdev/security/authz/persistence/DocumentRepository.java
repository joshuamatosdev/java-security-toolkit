package io.github.joshuamatosdev.security.authz.persistence;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentRepository extends JpaRepository<DocumentEntity, UUID> {

    /**
     * Tenant-scoped primary-key lookup: returns the document only when it belongs to {@code tenantId},
     * so a resource in another tenant is indistinguishable from a missing one and the tenant boundary
     * is never revealed as a 403-vs-404 existence oracle.
     */
    Optional<DocumentEntity> findByIdAndTenantId(UUID id, UUID tenantId);
}
