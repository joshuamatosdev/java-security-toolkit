package io.github.joshuamatosdev.security.authz.service;

import io.github.joshuamatosdev.security.authz.decision.DenialReason;

/**
 * Thrown by {@link AuthorizationService#enforce} when a decision denies the action — after the deny
 * has been written to the audit trail. Carries the {@link DenialReason} so a caller (e.g. an HTTP
 * error handler) can map it without re-deriving the cause.
 *
 * <p>Why this exists: the service layer is the single authorization decision point, preventing
 * callers from skipping audit or fine-grained resource checks.
 */
public final class AuthorizationDeniedException extends RuntimeException {

    private final DenialReason reason;

    public AuthorizationDeniedException(final DenialReason reason) {
        super("access denied: " + reason);
        this.reason = reason;
    }

    public DenialReason reason() {
        return reason;
    }
}
