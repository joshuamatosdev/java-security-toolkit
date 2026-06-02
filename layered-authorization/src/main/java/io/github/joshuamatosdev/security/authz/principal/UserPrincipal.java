package io.github.joshuamatosdev.security.authz.principal;

import java.util.Objects;

/**
 * A human actor, keyed by its identity-provider subject.
 */
public record UserPrincipal(String subject, String email, long authorizationVersion) implements PolicyPrincipal {

    public UserPrincipal {
        Objects.requireNonNull(subject, "subject must not be null");
        Objects.requireNonNull(email, "email must not be null");
    }

    @Override
    public PrincipalType principalType() {
        return PrincipalType.USER;
    }

    @Override
    public String principalKey() {
        return subject;
    }
}
