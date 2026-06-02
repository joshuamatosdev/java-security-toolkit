package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;

/**
 * Typed organization (team) identifier — a subtenant scope. An {@code ORGANIZATION}-scoped role
 * assignment grants a role only within the organization it names; a resource owned by an
 * organization can be reached by its members under an organization-scoped rule.
 */
public record OrganizationId(UUID value) {

    public OrganizationId {
        Objects.requireNonNull(value, "OrganizationId must not be null");
    }

    public static OrganizationId fromString(final String raw) {
        return new OrganizationId(UUID.fromString(raw));
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
