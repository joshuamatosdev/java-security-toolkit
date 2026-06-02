package io.github.joshuamatosdev.security.tenant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;

/**
 * A neutral tenant-scoped aggregate used to demonstrate isolation. {@code tenant_id} is
 * {@code insertable = false} / {@code updatable = false}: the database stamps it from the session
 * GUC ({@code app.current_tenant}) on insert, so a caller cannot write a row for another tenant
 * through the entity. The RLS policy's {@code WITH CHECK} backstops any raw write that tries.
 */
@Entity
@Table(name = "document")
public class DocumentEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", insertable = false, updatable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String body;

    protected DocumentEntity() {
        // JPA
    }

    public DocumentEntity(final UUID id, final String title, final String body) {
        this.id = id;
        this.title = title;
        this.body = body;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getTitle() {
        return title;
    }

    public String getBody() {
        return body;
    }
}
