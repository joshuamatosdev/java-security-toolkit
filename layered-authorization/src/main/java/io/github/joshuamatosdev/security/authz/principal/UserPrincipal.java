package io.github.joshuamatosdev.security.authz.principal;

import java.util.Objects;

/**
 * A human actor, keyed by its identity-provider subject.
 *
 * <p>Why this exists: typed principals keep human users and service clients distinct before route
 * gates or resource policies make decisions.
 */
public record UserPrincipal(String subject, String email, long authorizationVersion) implements PolicyPrincipal {

    public UserPrincipal {
        subject = requireNonBlank(subject, "subject");
        email = requireNonBlank(email, "email");
        if (authorizationVersion < 0) {
            throw new IllegalArgumentException("authorizationVersion must not be negative");
        }
    }

    @Override
    public PrincipalType principalType() {
        return PrincipalType.USER;
    }

    @Override
    public String principalKey() {
        return subject;
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
