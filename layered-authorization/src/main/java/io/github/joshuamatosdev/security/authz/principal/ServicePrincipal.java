package io.github.joshuamatosdev.security.authz.principal;

import java.util.Objects;

/**
 * A machine actor (another service / a client credential), keyed by its OAuth2 client id.
 *
 * <p>Why this exists: typed principals keep human users and service clients distinct before route
 * gates or resource policies make decisions.
 */
public record ServicePrincipal(String clientId, long authorizationVersion) implements PolicyPrincipal {

    public ServicePrincipal {
        clientId = requireNonBlank(clientId, "clientId");
        if (authorizationVersion < 0) {
            throw new IllegalArgumentException("authorizationVersion must not be negative");
        }
    }

    @Override
    public PrincipalType principalType() {
        return PrincipalType.SERVICE;
    }

    @Override
    public String principalKey() {
        return clientId;
    }

    private static String requireNonBlank(final String value, final String field) {
        Objects.requireNonNull(value, field + " must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        if (!value.equals(value.strip())) {
            throw new IllegalArgumentException(field + " must not include leading or trailing whitespace");
        }
        if (value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
        return value;
    }
}
