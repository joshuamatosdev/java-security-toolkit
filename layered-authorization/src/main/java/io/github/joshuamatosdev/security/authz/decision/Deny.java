package io.github.joshuamatosdev.security.authz.decision;

import java.util.Objects;

/**
 * A denied decision, carrying the {@link DenialReason}.
 */
public record Deny(DenialReason reason) implements Decision {

    public Deny {
        Objects.requireNonNull(reason, "Deny.reason must not be null");
    }
}
