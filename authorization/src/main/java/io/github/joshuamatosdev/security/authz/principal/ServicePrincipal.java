package io.github.joshuamatosdev.security.authz.principal;

import io.github.joshuamatosdev.security.shared.RequiredText;
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
        return RequiredText.require(value, field);
    }
}
