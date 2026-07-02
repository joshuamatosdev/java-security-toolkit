package io.github.joshuamatosdev.security.shared;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Typed team identifier — a grouping within an organization. A {@code TEAM}-scoped role assignment
 * grants a role only within the team it names. The team is a discretionary grant boundary in the
 * authorization layer, never a data-plane isolation dimension: tenants isolate, organizations
 * subdivide, teams group people for grants.
 *
 * <p>Why this exists: team identifiers participate in scoped authorization, so a dedicated type
 * prevents confusing team scope with organization, tenant, or resource identity.
 */
public record TeamId(UUID value) {

    public TeamId {
        Objects.requireNonNull(value, "TeamId must not be null");
        CanonicalUuid.requireNotNil(value, "TeamId");
    }

    public static TeamId fromString(final String raw) {
        return new TeamId(CanonicalUuid.parse(raw, "TeamId"));
    }

    @Override
    public @NonNull String toString() {
        return value.toString();
    }
}
