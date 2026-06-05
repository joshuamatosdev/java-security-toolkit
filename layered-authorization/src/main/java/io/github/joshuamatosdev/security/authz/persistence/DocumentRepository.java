package io.github.joshuamatosdev.security.authz.persistence;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * Document Repository for the layered-authorization module.
 *
 * <p>Why this exists: document persistence gives the policy database-backed owner and organization
 * facts rather than synthetic in-memory resources.
 */
public interface DocumentRepository extends Repository<DocumentEntity, UUID> {

    /**
     * Inserts a document while leaving primary-key creation to the database default.
     *
     * <p>The repository intentionally does not extend {@code JpaRepository}: inherited id-only reads,
     * deletes, and bulk methods would bypass the tenant-scoped boundary methods below.
     */
    <S extends DocumentEntity> S save(S entity);

    /**
     * Tenant-scoped primary-key lookup: returns the document only when it belongs to {@code tenantId},
     * so a resource in another tenant is indistinguishable from a missing one and the tenant boundary
     * is never revealed as a 403-vs-404 existence oracle.
     */
    Optional<DocumentEntity> findByIdAndTenantId(UUID id, UUID tenantId);

    /**
     * Tenant-scoped delete: the write carries the same outer tenant boundary as lookup, so a delete
     * can never degrade into an id-only operation.
     */
    @Transactional
    @Modifying
    @Query("DELETE FROM DocumentEntity d WHERE d.id = :id AND d.tenantId = :tenantId")
    int deleteByIdAndTenantId(@Param("id") UUID id, @Param("tenantId") UUID tenantId);
}
