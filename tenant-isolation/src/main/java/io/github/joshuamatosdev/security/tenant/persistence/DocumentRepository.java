package io.github.joshuamatosdev.security.tenant.persistence;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Plain Spring Data repository — deliberately with no tenant predicate anywhere. Isolation is the
 * database's job (RLS), not the query's. {@code findAll()} returns only the bound tenant's rows.
 *
 * <p>Why this exists: the module needs a tiny tenant-owned resource so RLS and placement behavior
 * can be demonstrated against real persisted rows.
 */
public interface DocumentRepository extends JpaRepository<DocumentEntity, UUID> {}
