package io.github.joshuamatosdev.security.tenant.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.UUID;
import org.hibernate.annotations.Generated;
import org.hibernate.generator.EventType;

/**
 * A neutral tenant-scoped aggregate used to demonstrate isolation.
 *
 * <p>{@code id} is {@code insertable = false} with {@link Generated @Generated(INSERT)}: the
 * database owns identifier creation. The {@code id_v7} domain default ({@code uuidv7()}, PG18) mints
 * a time-ordered UUIDv7 at insert and Hibernate reads it back via {@code RETURNING} — application
 * code never generates a primary key.
 *
 * <p>{@code tenant_id} is likewise {@code insertable = false} / {@code updatable = false}: the
 * database stamps it from the session claim ({@code app.tenant_claim}) on insert after verifying its
 * HMAC, so a caller cannot write a row for another tenant through the entity. The RLS policy's
 * {@code WITH CHECK} backstops any raw write action that tries.
 *
 * <p>Why this exists: the module needs a tiny tenant-owned resource so RLS and placement behavior
 * can be demonstrated against real persisted rows.
 */
@Entity
@Table(name = "document")
public class DocumentEntity {

    @Id
    @GeneratedValue
    @Generated(event = EventType.INSERT)
    @Column(name = "id", nullable = false, updatable = false, insertable = false)
    private UUID id;

    @Column(name = "tenant_id", insertable = false, updatable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false)
    private String body;

    /**
     * JPA-only constructor.
     *
     * <p>Application code should use {@link #DocumentEntity(String, String)} so the database remains
     * the only component that assigns {@code id} and {@code tenant_id}.
     */
    protected DocumentEntity() {
        // JPA
    }

    /**
     * Creates a document whose identity and tenant are assigned by PostgreSQL at insert time.
     *
     * @param title document title
     * @param body document body
     */
    public DocumentEntity(final String title, final String body) {
        this.title = title;
        this.body = body;
    }

    /**
     * Returns the database-generated UUIDv7 primary key.
     *
     * @return the document identifier, or {@code null} before the entity is inserted
     */
    public UUID getId() {
        return id;
    }

    /**
     * Returns the tenant stamped by the verified PostgreSQL session claim.
     *
     * @return the owning tenant identifier, or {@code null} before the entity is inserted
     */
    public UUID getTenantId() {
        return tenantId;
    }

    /**
     * Returns the document title.
     *
     * @return the title supplied by application code
     */
    public String getTitle() {
        return title;
    }

    /**
     * Returns the document body.
     *
     * @return the body supplied by application code
     */
    public String getBody() {
        return body;
    }
}
