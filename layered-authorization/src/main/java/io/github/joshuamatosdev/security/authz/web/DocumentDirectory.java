package io.github.joshuamatosdev.security.authz.web;

import io.github.joshuamatosdev.security.authz.request.ProtectedResource;
import io.github.joshuamatosdev.security.shared.OrganizationId;
import io.github.joshuamatosdev.security.shared.ResourceId;
import io.github.joshuamatosdev.security.shared.TenantId;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * An in-memory store of document facts so the controller can build a {@link ProtectedResource} to
 * authorize against — no database needed for the authorization showcase. Seeded with deterministic
 * IDs (exposed as constants) so the slice tests can reference them.
 *
 * <p>Neutral fictional data: tenant "acme", organization "engineering", a document owned by the
 * demo {@code member} account and another owned by someone else.
 */
@Component
public class DocumentDirectory {

    // --- Deterministic demo identifiers (neutral, fictional) ---
    public static final TenantId ACME = TenantId.fromString("11111111-1111-1111-1111-111111111111");
    public static final OrganizationId ENGINEERING =
        OrganizationId.fromString("22222222-2222-2222-2222-222222222222");
    public static final ResourceId OWNED_BY_MEMBER =
        ResourceId.fromString("33333333-3333-3333-3333-333333333333");
    public static final ResourceId OWNED_BY_OTHER =
        ResourceId.fromString("44444444-4444-4444-4444-444444444444");

    private final Map<UUID, ProtectedResource> byId = Map.of(
        OWNED_BY_MEMBER.value(), new ProtectedResource(OWNED_BY_MEMBER, ACME, ENGINEERING, "member"),
        OWNED_BY_OTHER.value(), new ProtectedResource(OWNED_BY_OTHER, ACME, ENGINEERING, "someone-else"));

    public Optional<ProtectedResource> find(final ResourceId id) {
        return Optional.ofNullable(byId.get(id.value()));
    }
}
