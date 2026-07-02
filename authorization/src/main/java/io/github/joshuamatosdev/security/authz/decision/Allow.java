package io.github.joshuamatosdev.security.authz.decision;

import java.util.Objects;

/**
 * A granted decision, carrying the {@link GrantBasis} that permitted the action.
 *
 * <p>Why this exists: sealed decision types make allow and deny outcomes carry their enforcement
 * and audit rationale explicitly.
 */
public record Allow(GrantBasis basis) implements Decision {

    public Allow {
        Objects.requireNonNull(basis, "Allow.basis must not be null");
    }
}
