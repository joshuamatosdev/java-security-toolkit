package io.github.joshuamatosdev.security.crypto.api;

import java.util.Objects;

/** Audit event emitted by {@link DocumentSigner}. */
public record SignatureAuditEvent(
        Operation operation,
        String alg,
        String keyId,
        boolean success,
        String reason) {

    /** Signing lifecycle operation. */
    public enum Operation {
        SIGN,
        VERIFY
    }

    public SignatureAuditEvent {
        operation = Objects.requireNonNull(operation, "operation must not be null");
        reason = Objects.requireNonNull(reason, "reason must not be null");
    }
}
