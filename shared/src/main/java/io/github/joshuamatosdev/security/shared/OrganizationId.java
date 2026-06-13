package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Typed organization (team) identifier — a subtenant scope. An {@code ORGANIZATION}-scoped role
 * assignment grants a role only within the organization it names; a resource owned by an
 * organization can be reached by its members under an organization-scoped rule.
 *
 * <p>Why this exists: organization identifiers participate in scoped authorization, so a dedicated
 * type prevents confusing organization scope with tenant or resource identity.
 */
public record OrganizationId(UUID value) {

    public OrganizationId {
        Objects.requireNonNull(value, "OrganizationId must not be null");
        CanonicalUuid.requireNotNil(value, "OrganizationId");
    }

    public static OrganizationId fromString(final String raw) {
        return new OrganizationId(CanonicalUuid.parse(raw, "OrganizationId"));
    }

    @Override
    public @NonNull String toString() {
        return value.toString();
    }
}
