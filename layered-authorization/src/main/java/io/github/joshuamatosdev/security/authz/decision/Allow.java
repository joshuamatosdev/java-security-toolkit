package io.github.joshuamatosdev.security.authz.decision;

import java.util.Objects;

/**
 * A granted decision, carrying the {@link GrantBasis} that permitted the action.
 */
public record Allow(GrantBasis basis) implements Decision {

    public Allow {
        Objects.requireNonNull(basis, "Allow.basis must not be null");
    }
}
