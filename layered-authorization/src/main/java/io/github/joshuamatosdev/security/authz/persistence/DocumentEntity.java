package io.github.joshuamatosdev.security.authz.persistence;

import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;
import org.jspecify.annotations.Nullable;

/**
 * Document facts used by the authorization demo.
 *
 * <p>The primary key is database-owned. PostgreSQL 18 mints a UUIDv7 through the {@code id_v7}
 * domain default ({@code uuidv7()}); Hibernate reads the inserted value back instead of generating a
 * UUID in application code.
 */
@Entity
@Table(name = "document")
public class DocumentEntity {

    @Id
    @GeneratedValue
    @Generated(event = EventType.INSERT)
    @Column(name = "id", nullable = false, updatable = false, insertable = false)
    private UUID id;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "organization_id", updatable = false)
    private UUID organizationId;

    @Column(name = "owner_principal_key")
    private String ownerPrincipalKey;

    protected DocumentEntity() {
        // JPA
    }

    public DocumentEntity(
        final TenantId tenantId,
        @Nullable final OrganizationId organizationId,
        @Nullable final String ownerPrincipalKey) {
        this.tenantId = tenantId.value();
        this.organizationId = organizationId == null ? null : organizationId.value();
        this.ownerPrincipalKey = ownerPrincipalKey;
    }

    public UUID getId() {
        return id;
    }

    public ProtectedResource toProtectedResource() {
        return new ProtectedResource(
            new ResourceId(id),
            new TenantId(tenantId),
            organizationId == null ? null : new OrganizationId(organizationId),
            ownerPrincipalKey);
    }
}
