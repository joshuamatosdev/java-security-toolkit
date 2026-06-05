package io.github.joshuamatosdev.security.authz.web.document;

import io.github.joshuamatosdev.security.authz.persistence.DocumentEntity;
import io.github.joshuamatosdev.security.authz.persistence.DocumentRepository;
import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Database-backed lookup of document facts so the controller can build a {@link ProtectedResource}
 * to authorize against. PostgreSQL owns document identifier creation through the {@code id_v7}
 * domain default; this component only reads and deletes by already-known resource ids.
 *
 * <p>Neutral fictional tenant and organization identifiers support the demo actor profile.
 *
 * <p>Why this exists: document web components provide the resource-backed endpoint used to
 * demonstrate route gates plus fine-grained policy.
 */
@Component
public class DocumentDirectory {

    // --- Deterministic demo identifiers (neutral, fictional) ---
    public static final TenantId ACME = TenantId.fromString("11111111-1111-1111-1111-111111111111");
    public static final OrganizationId ENGINEERING =
        OrganizationId.fromString("22222222-2222-2222-2222-222222222222");

    private final DocumentRepository repository;

    public DocumentDirectory(final DocumentRepository repository) {
        this.repository = repository;
    }

    public Optional<ProtectedResource> find(final TenantId tenantId, final ResourceId id) {
        return repository
            .findByIdAndTenantId(id.value(), tenantId.value())
            .map(DocumentEntity::toProtectedResource);
    }

    public void delete(final TenantId tenantId, final ResourceId id) {
        repository.deleteByIdAndTenantId(id.value(), tenantId.value());
    }

    public ProtectedResource create(
        final TenantId tenantId,
        final OrganizationId organizationId,
        final String ownerPrincipalKey) {
        return repository.save(new DocumentEntity(tenantId, organizationId, ownerPrincipalKey)).toProtectedResource();
    }
}
