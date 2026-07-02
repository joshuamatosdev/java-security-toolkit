package io.github.joshuamatosdev.security.authz.principal;

import io.github.joshuamatosdev.security.shared.RequiredText;
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
        return RequiredText.require(value, field);
    }
}
