package io.github.joshuamatosdev.security.authz.decision;

/**
 * The outcome of an authorization decision: exactly an {@link Allow} (with the basis that granted it)
 * or a {@link Deny} (with the reason). Sealed so callers must handle both — there is no implicit
 * third "unknown" outcome that could be treated as a permit.
 *
 * <p>Why this exists: sealed decision types make allow and deny outcomes carry their enforcement
 * and audit rationale explicitly.
 */
public sealed interface Decision permits Allow, Deny {

    default boolean allowed() {
        return this instanceof Allow;
    }

    default boolean denied() {
        return this instanceof Deny;
    }
}
