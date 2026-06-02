package io.github.joshuamatosdev.security.authz.principal;

import java.util.Objects;

/**
 * A machine actor (another service / a client credential), keyed by its OAuth2 client id.
 */
public record ServicePrincipal(String clientId, long authorizationVersion) implements PolicyPrincipal {

    public ServicePrincipal {
        Objects.requireNonNull(clientId, "clientId must not be null");
    }

    @Override
    public PrincipalType principalType() {
        return PrincipalType.SERVICE;
    }

    @Override
    public String principalKey() {
        return clientId;
    }
}
